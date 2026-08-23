(function installCopyableExamples(global) {
  'use strict';

  const DEFAULTS = Object.freeze({
    selector: 'pre > code',
    codeIdPrefix: 'code-example',
    promptIdPrefix: 'prompt-example',
    maxBlocks: 10000,
    maxBytes: 1048576,
    resetAfterMs: 1800,
    codeCopyLabel: 'Copy code',
    promptCopyLabel: 'Copy prompt',
    codeCopiedLabel: 'Code copied',
    promptCopiedLabel: 'Prompt copied',
    errorLabel: 'Copy failed',
  });

  function boundedInteger(value, fallback, minimum, maximum) {
    return Number.isSafeInteger(value) && value >= minimum && value <= maximum
      ? value
      : fallback;
  }

  function stringOption(value, fallback) {
    return typeof value === 'string' && value ? value : fallback;
  }

  function idPrefix(value, fallback) {
    return typeof value === 'string' && /^[a-z][a-z0-9-]*$/i.test(value) ? value : fallback;
  }

  function normalizeOptions(options) {
    const source = options && typeof options === 'object' ? options : {};
    return {
      selector: stringOption(source.selector, DEFAULTS.selector),
      codeIdPrefix: idPrefix(source.codeIdPrefix || source.idPrefix, DEFAULTS.codeIdPrefix),
      promptIdPrefix: idPrefix(source.promptIdPrefix, DEFAULTS.promptIdPrefix),
      maxBlocks: boundedInteger(source.maxBlocks, DEFAULTS.maxBlocks, 1, DEFAULTS.maxBlocks),
      maxBytes: boundedInteger(source.maxBytes, DEFAULTS.maxBytes, 1, DEFAULTS.maxBytes),
      resetAfterMs: boundedInteger(source.resetAfterMs, DEFAULTS.resetAfterMs, 0, 60000),
      codeCopyLabel: stringOption(source.codeCopyLabel || source.copyLabel, DEFAULTS.codeCopyLabel),
      promptCopyLabel: stringOption(source.promptCopyLabel, DEFAULTS.promptCopyLabel),
      codeCopiedLabel: stringOption(
        source.codeCopiedLabel || source.copiedLabel,
        DEFAULTS.codeCopiedLabel,
      ),
      promptCopiedLabel: stringOption(source.promptCopiedLabel, DEFAULTS.promptCopiedLabel),
      errorLabel: stringOption(source.errorLabel, DEFAULTS.errorLabel),
    };
  }

  function sourceText(element) {
    return typeof element?.textContent === 'string' ? element.textContent : '';
  }

  function byteLength(text) {
    if (typeof TextEncoder === 'function') {
      return new TextEncoder().encode(text).byteLength;
    }
    return unescape(encodeURIComponent(text)).length;
  }

  async function copyText(text, environment) {
    const env = environment || {};
    const navigatorObject = env.navigator || global.navigator;
    const documentObject = env.document || global.document;

    if (navigatorObject?.clipboard?.writeText) {
      try {
        await navigatorObject.clipboard.writeText(text);
        return 'clipboard';
      } catch {
        // Continue to the synchronous fallback.
      }
    }

    if (!documentObject?.body || typeof documentObject.execCommand !== 'function') {
      throw new Error('Clipboard unavailable');
    }

    const textarea = documentObject.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', '');
    textarea.setAttribute('aria-hidden', 'true');
    textarea.style.position = 'fixed';
    textarea.style.inset = '-9999px auto auto -9999px';
    textarea.style.opacity = '0';
    documentObject.body.appendChild(textarea);

    try {
      textarea.focus?.();
      textarea.select?.();
      textarea.setSelectionRange?.(0, textarea.value.length);
      if (!documentObject.execCommand('copy')) {
        throw new Error('Clipboard fallback failed');
      }
      return 'fallback';
    } finally {
      textarea.remove();
    }
  }

  function exampleKind(code) {
    const codeKind = code.getAttribute?.('data-copy-kind');
    const preKind = code.parentElement?.getAttribute?.('data-copy-kind');
    if (codeKind && preKind && codeKind !== preKind) {
      return null;
    }
    const declared = codeKind || preKind;
    if (declared === null || declared === undefined || declared === '') {
      return 'code';
    }
    return declared === 'code' || declared === 'prompt' ? declared : null;
  }

  function slug(value) {
    const normalized = String(value || '')
      .normalize('NFKD')
      .replace(/[\u0300-\u036f]/g, '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '');
    return normalized || 'page';
  }

  function exampleMetadata(root, elements, options) {
    const selected = new Set(elements);
    const sectionCounts = new Map();
    const metadata = new Map();
    let section = slug(global.location?.pathname?.split('/').pop()?.replace(/\.[^.]+$/, ''));
    const ordered = root.querySelectorAll(
      `h1[id], h2[id], h3[id], h4[id], h5[id], h6[id], ${options.selector}`,
    );

    for (const element of ordered) {
      if (/^H[1-6]$/.test(element.tagName) && element.id) {
        section = slug(element.id);
        continue;
      }
      if (!selected.has(element)) {
        continue;
      }
      const kind = exampleKind(element);
      if (!kind) {
        continue;
      }
      const countKey = `${kind}:${section}`;
      const ordinal = (sectionCounts.get(countKey) || 0) + 1;
      sectionCounts.set(countKey, ordinal);
      const prefix = kind === 'prompt' ? options.promptIdPrefix : options.codeIdPrefix;
      metadata.set(element, { kind, ordinal, id: `${prefix}-${section}-${ordinal}` });
    }
    return metadata;
  }

  function labels(kind, options) {
    return kind === 'prompt'
      ? {
          idle: options.promptCopyLabel,
          copied: options.promptCopiedLabel,
          noun: 'prompt',
        }
      : {
          idle: options.codeCopyLabel,
          copied: options.codeCopiedLabel,
          noun: 'code',
        };
  }

  function setState(button, status, state, kindLabels, options) {
    const label = state === 'copied' ? kindLabels.copied : options.errorLabel;
    button.dataset.state = state;
    button.textContent = label;
    status.textContent = label;

    if (options.resetAfterMs > 0) {
      global.setTimeout(() => {
        button.dataset.state = 'idle';
        button.textContent = kindLabels.idle;
        status.textContent = '';
      }, options.resetAfterMs);
    }
  }

  function createElement(root, tag) {
    return root.createElement ? root.createElement(tag) : global.document.createElement(tag);
  }

  function decorate(root, code, metadata, globalOrdinal, options) {
    const pre = code.parentElement;
    if (!pre) {
      return false;
    }
    const kindLabels = labels(metadata.kind, options);

    let wrapper = pre.parentElement;
    if (!wrapper?.matches?.('[data-copy-example]')) {
      wrapper = createElement(root, 'div');
      wrapper.className = `copy-example copy-${metadata.kind}-example`;
      wrapper.dataset.copyExample = '';
      pre.parentNode.insertBefore(wrapper, pre);
      wrapper.appendChild(pre);
    }
    wrapper.dataset.copyKind = metadata.kind;
    if (!wrapper.id) {
      wrapper.id = metadata.id;
    }
    wrapper.setAttribute('tabindex', '-1');

    let toolbar = wrapper.querySelector(':scope > .copy-example-toolbar');
    if (!toolbar) {
      toolbar = createElement(root, 'div');
      toolbar.className = 'copy-example-toolbar';
      wrapper.insertBefore(toolbar, pre);
    }

    const existingButtons = [...toolbar.querySelectorAll('[data-copy-example-button]')];
    let button = existingButtons.shift();
    for (const duplicate of existingButtons) {
      duplicate.remove();
    }

    let status = toolbar.querySelector('[data-copy-example-status]');
    if (!status) {
      status = createElement(root, 'span');
      status.className = 'copy-example-status';
      status.dataset.copyExampleStatus = '';
      status.setAttribute('role', 'status');
      status.setAttribute('aria-live', 'polite');
      status.setAttribute('aria-atomic', 'true');
      toolbar.appendChild(status);
    }

    let permalink = toolbar.querySelector('[data-copy-example-link]');
    if (!permalink) {
      permalink = createElement(root, 'a');
      permalink.className = 'copy-example-link';
      permalink.dataset.copyExampleLink = '';
      permalink.textContent = '#';
      toolbar.appendChild(permalink);
    }
    permalink.href = `#${wrapper.id}`;
    permalink.setAttribute(
      'aria-label',
      `Link to ${kindLabels.noun} example ${metadata.ordinal}`,
    );

    if (!button) {
      button = createElement(root, 'button');
      button.type = 'button';
      button.className = 'copy-example-button';
      button.dataset.copyExampleButton = '';
      button.dataset.state = 'idle';
      toolbar.appendChild(button);
      button.addEventListener('click', async () => {
        const text = sourceText(code);
        if (byteLength(text) > options.maxBytes) {
          setState(button, status, 'error', kindLabels, options);
          return;
        }
        try {
          await copyText(text);
          setState(button, status, 'copied', kindLabels, options);
        } catch {
          setState(button, status, 'error', kindLabels, options);
        }
      });
    }
    button.textContent = button.dataset.state === 'idle' ? kindLabels.idle : button.textContent;
    button.setAttribute(
      'aria-label',
      `${kindLabels.idle} example ${metadata.ordinal}`,
    );
    button.dataset.copyKind = metadata.kind;
    wrapper.dataset.copyOrdinal = String(globalOrdinal);
    return true;
  }

  function enhanceCopyableExamples(root, options) {
    const target = root || global.document;
    if (!target?.querySelectorAll) {
      throw new TypeError('A Document or Element root is required');
    }
    const normalized = normalizeOptions(options);
    const selected = [...target.querySelectorAll(normalized.selector)].slice(0, normalized.maxBlocks);
    const metadata = exampleMetadata(target, selected, normalized);
    let enhanced = 0;
    for (const code of selected) {
      const details = metadata.get(code);
      if (details && decorate(target, code, details, enhanced + 1, normalized)) {
        enhanced += 1;
      }
    }
    const hash = global.location?.hash;
    if (hash && /^#[a-z0-9-]+$/i.test(hash)) {
      const linked = target.getElementById?.(hash.slice(1)) || target.querySelector?.(hash);
      linked?.scrollIntoView?.();
    }
    return enhanced;
  }

  const api = Object.freeze({
    defaults: DEFAULTS,
    sourceText,
    copyText,
    exampleKind,
    enhanceCopyableExamples,
    enhanceCodeDocs: enhanceCopyableExamples,
  });
  global.CleverGirlCopyExamples = api;
  global.CleverGirlCopyCodeDocs = api;

  const currentScript = global.document?.currentScript;
  const manual = currentScript?.hasAttribute('data-copy-examples-manual')
    || currentScript?.hasAttribute('data-copy-code-docs-manual');
  if (global.document && !manual) {
    const start = () => enhanceCopyableExamples(global.document);
    if (global.document.readyState === 'loading') {
      global.document.addEventListener('DOMContentLoaded', start, { once: true });
    } else {
      start();
    }
  }
})(typeof window === 'object' ? window : globalThis);

(function installCopyableExamples(global) {
  'use strict';

  const DEFAULTS = Object.freeze({
    selector: 'pre > code',
    codeIdPrefix: 'code-example',
    promptIdPrefix: 'prompt-example',
    maxBlocks: 10000,
    maxBytes: 1048576,
    copiedResetAfterMs: 1600,
    errorResetAfterMs: 5000,
    codeCopyLabel: 'Copy code',
    promptCopyLabel: 'Copy prompt',
    copiedLabel: 'Copied',
    manualCopyLabel: 'Press Ctrl/Cmd+C',
    promptHint: 'Paste into any AI you choose and adapt it to your context.',
  });

  const LINE_NUMBER_SELECTOR = '.lineno, .line-number, [data-line-number], .rouge-gutter';

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
      copiedResetAfterMs: boundedInteger(
        source.copiedResetAfterMs ?? source.resetAfterMs,
        DEFAULTS.copiedResetAfterMs,
        0,
        60000,
      ),
      errorResetAfterMs: boundedInteger(
        source.errorResetAfterMs ?? source.resetAfterMs,
        DEFAULTS.errorResetAfterMs,
        0,
        60000,
      ),
      codeCopyLabel: stringOption(source.codeCopyLabel || source.copyLabel, DEFAULTS.codeCopyLabel),
      promptCopyLabel: stringOption(source.promptCopyLabel, DEFAULTS.promptCopyLabel),
      copiedLabel: stringOption(source.copiedLabel, DEFAULTS.copiedLabel),
      manualCopyLabel: stringOption(source.manualCopyLabel, DEFAULTS.manualCopyLabel),
      promptHint: stringOption(source.promptHint, DEFAULTS.promptHint),
    };
  }

  function sourceText(element) {
    if (!element?.cloneNode) {
      return typeof element?.textContent === 'string' ? element.textContent : '';
    }
    const clean = element.cloneNode(true);
    clean.querySelectorAll?.(LINE_NUMBER_SELECTOR).forEach((node) => node.remove());
    return typeof clean.textContent === 'string' ? clean.textContent : '';
  }

  function byteLength(text) {
    if (typeof TextEncoder === 'function') {
      return new TextEncoder().encode(text).byteLength;
    }
    return unescape(encodeURIComponent(text)).length;
  }

  function restoreSelection(selection, ranges) {
    if (!selection) return;
    try {
      selection.removeAllRanges();
      ranges.forEach((range) => selection.addRange(range));
    } catch {
      // Saved ranges can become stale when the page changes during a copy.
    }
  }

  function focusWithoutScrolling(element) {
    if (!element || typeof element.focus !== 'function') return;
    try {
      element.focus({ preventScroll: true });
    } catch {
      try {
        element.focus();
      } catch {
        // Copying can still succeed when scripted focus is blocked.
      }
    }
  }

  async function copyText(text, environment) {
    const env = environment || {};
    const navigatorObject = env.navigator || global.navigator;
    const documentObject = env.document || global.document;
    const windowObject = env.window || global;
    const secureContext = env.isSecureContext ?? windowObject?.isSecureContext;

    if (secureContext && navigatorObject?.clipboard?.writeText) {
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
    const selection = windowObject?.getSelection?.() || null;
    const ranges = [];
    const activeElement = documentObject.activeElement;
    if (selection) {
      for (let index = 0; index < selection.rangeCount; index += 1) {
        ranges.push(selection.getRangeAt(index).cloneRange());
      }
    }
    textarea.value = text;
    textarea.readOnly = true;
    textarea.setAttribute('aria-hidden', 'true');
    textarea.style.position = 'fixed';
    textarea.style.top = '0';
    textarea.style.left = '-9999px';
    textarea.style.opacity = '0';
    documentObject.body.appendChild(textarea);

    try {
      focusWithoutScrolling(textarea);
      textarea.select?.();
      textarea.setSelectionRange?.(0, textarea.value.length);
      if (!documentObject.execCommand('copy')) {
        throw new Error('Clipboard fallback failed');
      }
      return 'fallback';
    } finally {
      textarea.remove();
      restoreSelection(selection, ranges);
      focusWithoutScrolling(activeElement);
    }
  }

  function selectSource(source) {
    const selection = global.getSelection?.();
    if (!selection || !global.document?.createRange) return;
    try {
      focusWithoutScrolling(source);
      const range = global.document.createRange();
      range.selectNodeContents(source);
      selection.removeAllRanges();
      selection.addRange(range);
    } catch {
      // The readable source remains in place if selection is sandboxed.
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
          noun: 'prompt',
          title: 'Prompt',
        }
      : {
          idle: options.codeCopyLabel,
          noun: 'code',
          title: 'Code',
        };
  }

  function setState(button, status, state, kindLabels, options, source) {
    const label = button.querySelector('.copy-example-label');
    const copied = state === 'copied';
    const stateLabel = copied ? options.copiedLabel : options.manualCopyLabel;
    global.clearTimeout?.(Number(button.dataset.copyTimer || 0));
    button.dataset.state = state;
    button.classList.toggle('is-copied', copied);
    if (label) label.textContent = stateLabel;
    if (copied) {
      status.textContent = `${kindLabels.title} copied to clipboard.`;
    } else {
      selectSource(source);
      status.textContent = `Automatic copy is unavailable. The complete ${kindLabels.noun} is selected; press Control or Command plus C to copy.`;
    }

    const resetAfterMs = copied ? options.copiedResetAfterMs : options.errorResetAfterMs;
    if (resetAfterMs > 0) {
      const timer = global.setTimeout(() => {
        button.classList.remove('is-copied');
        button.dataset.state = 'idle';
        if (label) label.textContent = kindLabels.idle;
      }, resetAfterMs);
      button.dataset.copyTimer = String(timer);
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
    if (!code.id) {
      code.id = `${wrapper.id}-text`;
    }

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
    status.id = `${wrapper.id}-status`;

    let hint = toolbar.querySelector('[data-copy-example-hint]');
    if (metadata.kind === 'prompt' && !hint) {
      hint = createElement(root, 'p');
      hint.className = 'copy-example-hint';
      hint.dataset.copyExampleHint = '';
      hint.id = `${wrapper.id}-hint`;
      hint.textContent = options.promptHint;
      toolbar.appendChild(hint);
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
      const icon = createElement(root, 'span');
      icon.className = 'copy-example-icon';
      icon.setAttribute('aria-hidden', 'true');
      icon.textContent = '⧉';
      const label = createElement(root, 'span');
      label.className = 'copy-example-label';
      label.textContent = kindLabels.idle;
      button.appendChild(icon);
      button.appendChild(label);
      toolbar.appendChild(button);
      button.addEventListener('click', async () => {
        status.textContent = '';
        const text = sourceText(code);
        if (byteLength(text) > options.maxBytes) {
          setState(button, status, 'error', kindLabels, options, code);
          return;
        }
        try {
          await copyText(text);
          setState(button, status, 'copied', kindLabels, options, code);
        } catch {
          setState(button, status, 'error', kindLabels, options, code);
        }
      });
    }
    button.setAttribute(
      'aria-label',
      `${kindLabels.idle} to clipboard`,
    );
    button.setAttribute('aria-controls', code.id);
    button.setAttribute(
      'aria-describedby',
      hint ? `${hint.id} ${status.id}` : status.id,
    );
    button.dataset.copyKind = metadata.kind;
    if (hint) toolbar.appendChild(hint);
    toolbar.appendChild(status);
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

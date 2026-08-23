(function installCopyCodeDocs(global) {
  'use strict';

  const DEFAULTS = Object.freeze({
    selector: 'pre > code',
    idPrefix: 'code-example',
    maxBlocks: 10000,
    maxBytes: 1048576,
    resetAfterMs: 1800,
    copyLabel: 'Copy',
    copiedLabel: 'Copied',
    errorLabel: 'Copy failed',
  });

  function boundedInteger(value, fallback, minimum, maximum) {
    return Number.isSafeInteger(value) && value >= minimum && value <= maximum
      ? value
      : fallback;
  }

  function normalizeOptions(options) {
    const source = options && typeof options === 'object' ? options : {};
    return {
      selector: typeof source.selector === 'string' && source.selector
        ? source.selector
        : DEFAULTS.selector,
      idPrefix: typeof source.idPrefix === 'string' && /^[a-z][a-z0-9-]*$/i.test(source.idPrefix)
        ? source.idPrefix
        : DEFAULTS.idPrefix,
      maxBlocks: boundedInteger(source.maxBlocks, DEFAULTS.maxBlocks, 1, DEFAULTS.maxBlocks),
      maxBytes: boundedInteger(source.maxBytes, DEFAULTS.maxBytes, 1, DEFAULTS.maxBytes),
      resetAfterMs: boundedInteger(source.resetAfterMs, DEFAULTS.resetAfterMs, 0, 60000),
      copyLabel: typeof source.copyLabel === 'string' && source.copyLabel
        ? source.copyLabel
        : DEFAULTS.copyLabel,
      copiedLabel: typeof source.copiedLabel === 'string' && source.copiedLabel
        ? source.copiedLabel
        : DEFAULTS.copiedLabel,
      errorLabel: typeof source.errorLabel === 'string' && source.errorLabel
        ? source.errorLabel
        : DEFAULTS.errorLabel,
    };
  }

  function sourceText(code) {
    return typeof code?.textContent === 'string' ? code.textContent : '';
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

  function slug(value) {
    const normalized = String(value || '')
      .normalize('NFKD')
      .replace(/[\u0300-\u036f]/g, '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '');
    return normalized || 'page';
  }

  function exampleIds(root, codes, prefix) {
    const codeSet = new Set(codes);
    const sectionCounts = new Map();
    const ids = new Map();
    let section = slug(global.location?.pathname?.split('/').pop()?.replace(/\.[^.]+$/, ''));
    const ordered = root.querySelectorAll('h1[id], h2[id], h3[id], h4[id], h5[id], h6[id], pre > code');

    for (const element of ordered) {
      if (/^H[1-6]$/.test(element.tagName) && element.id) {
        section = slug(element.id);
        continue;
      }
      if (!codeSet.has(element)) {
        continue;
      }
      const index = (sectionCounts.get(section) || 0) + 1;
      sectionCounts.set(section, index);
      ids.set(element, `${prefix}-${section}-${index}`);
    }

    for (const code of codes) {
      if (!ids.has(code)) {
        const index = (sectionCounts.get(section) || 0) + 1;
        sectionCounts.set(section, index);
        ids.set(code, `${prefix}-${section}-${index}`);
      }
    }
    return ids;
  }

  function setState(button, status, state, options) {
    const label = state === 'copied' ? options.copiedLabel : options.errorLabel;
    button.dataset.state = state;
    button.textContent = label;
    status.textContent = label;

    if (options.resetAfterMs > 0) {
      global.setTimeout(() => {
        button.dataset.state = 'idle';
        button.textContent = options.copyLabel;
        status.textContent = '';
      }, options.resetAfterMs);
    }
  }

  function decorate(root, code, id, ordinal, options) {
    const pre = code.parentElement;
    if (!pre) {
      return false;
    }

    let wrapper = pre.parentElement;
    if (!wrapper?.matches?.('[data-copy-code-docs]')) {
      wrapper = root.createElement ? root.createElement('div') : global.document.createElement('div');
      wrapper.className = 'copy-code-example';
      wrapper.dataset.copyCodeDocs = '';
      pre.parentNode.insertBefore(wrapper, pre);
      wrapper.appendChild(pre);
    }

    if (!wrapper.id) {
      wrapper.id = id;
    }
    wrapper.setAttribute('tabindex', '-1');

    let toolbar = wrapper.querySelector(':scope > .copy-code-toolbar');
    if (!toolbar) {
      toolbar = global.document.createElement('div');
      toolbar.className = 'copy-code-toolbar';
      wrapper.insertBefore(toolbar, pre);
    }

    const existingButtons = [...toolbar.querySelectorAll('[data-copy-code-button]')];
    let button = existingButtons.shift();
    for (const duplicate of existingButtons) {
      duplicate.remove();
    }

    let status = toolbar.querySelector('[data-copy-code-status]');
    if (!status) {
      status = global.document.createElement('span');
      status.className = 'copy-code-status';
      status.dataset.copyCodeStatus = '';
      status.setAttribute('role', 'status');
      status.setAttribute('aria-live', 'polite');
      status.setAttribute('aria-atomic', 'true');
      toolbar.appendChild(status);
    }

    let permalink = toolbar.querySelector('[data-copy-code-link]');
    if (!permalink) {
      permalink = global.document.createElement('a');
      permalink.className = 'copy-code-link';
      permalink.dataset.copyCodeLink = '';
      permalink.textContent = '#';
      toolbar.appendChild(permalink);
    }
    permalink.href = `#${wrapper.id}`;
    permalink.setAttribute('aria-label', `Link to code example ${ordinal}`);

    if (!button) {
      button = global.document.createElement('button');
      button.type = 'button';
      button.className = 'copy-code-button';
      button.dataset.copyCodeButton = '';
      button.dataset.state = 'idle';
      button.textContent = options.copyLabel;
      toolbar.appendChild(button);
      button.addEventListener('click', async () => {
        const text = sourceText(code);
        if (byteLength(text) > options.maxBytes) {
          setState(button, status, 'error', options);
          return;
        }
        try {
          await copyText(text);
          setState(button, status, 'copied', options);
        } catch {
          setState(button, status, 'error', options);
        }
      });
    }
    button.setAttribute('aria-label', `Copy code example ${ordinal}`);
    return true;
  }

  function enhanceCodeDocs(root, options) {
    const target = root || global.document;
    if (!target?.querySelectorAll) {
      throw new TypeError('A Document or Element root is required');
    }
    const normalized = normalizeOptions(options);
    const codes = [...target.querySelectorAll(normalized.selector)].slice(0, normalized.maxBlocks);
    const ids = exampleIds(target, codes, normalized.idPrefix);
    let enhanced = 0;
    codes.forEach((code, index) => {
      if (decorate(target, code, ids.get(code), index + 1, normalized)) {
        enhanced += 1;
      }
    });
    const hash = global.location?.hash;
    if (hash && /^#[a-z0-9-]+$/i.test(hash)) {
      const linked = (target.getElementById?.(hash.slice(1))
        || target.querySelector?.(hash));
      linked?.scrollIntoView?.();
    }
    return enhanced;
  }

  const api = Object.freeze({
    defaults: DEFAULTS,
    sourceText,
    copyText,
    enhanceCodeDocs,
  });
  global.CleverGirlCopyCodeDocs = api;

  if (global.document && !global.document.currentScript?.hasAttribute('data-copy-code-docs-manual')) {
    const start = () => enhanceCodeDocs(global.document);
    if (global.document.readyState === 'loading') {
      global.document.addEventListener('DOMContentLoaded', start, { once: true });
    } else {
      start();
    }
  }
})(typeof window === 'object' ? window : globalThis);

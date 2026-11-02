// Conservative Luau whitespace/comment minimizer. This is not a compiler or strong obfuscator.
function longBracketOpen(source, i) {
  if (source[i] !== '[') return null;
  let j = i + 1;
  while (source[j] === '=') j++;
  if (source[j] !== '[') return null;
  return { equals: j - i - 1, length: j - i + 1 };
}
function longBracketClose(source, i, equals) {
  const close = ']' + '='.repeat(equals) + ']';
  return source.startsWith(close, i) ? close.length : 0;
}

export function validateBasic(source) {
  const pairs = { ')': '(', ']': '[', '}': '{' };
  const stack = [];
  let quote = null, escaped = false, lineComment = false, longMode = null;
  for (let i = 0; i < source.length; i++) {
    const c = source[i], n = source[i + 1];
    if (lineComment) { if (c === '\n') lineComment = false; continue; }
    if (longMode) {
      const closeLen = longBracketClose(source, i, longMode.equals);
      if (closeLen) { i += closeLen - 1; longMode = null; }
      continue;
    }
    if (quote) { if (escaped) escaped = false; else if (c === '\\') escaped = true; else if (c === quote) quote = null; continue; }
    if (c === '-' && n === '-') {
      const open = longBracketOpen(source, i + 2);
      if (open) { longMode = { equals: open.equals, comment: true }; i += open.length + 1; }
      else { lineComment = true; i++; }
      continue;
    }
    const open = longBracketOpen(source, i);
    if (open) { longMode = { equals: open.equals, comment: false }; i += open.length - 1; continue; }
    if (c === '"' || c === "'") { quote = c; continue; }
    if ('([{'.includes(c)) stack.push({ c, i });
    else if (pairs[c]) {
      const top = stack.pop();
      if (!top || top.c !== pairs[c]) return { ok: false, note: `Mismatched delimiter near character ${i}.` };
    }
  }
  if (quote) return { ok: false, note: 'Unclosed string literal.' };
  if (longMode) return { ok: false, note: longMode.comment ? 'Unclosed long comment.' : 'Unclosed long string.' };
  if (stack.length) return { ok: false, note: `Unclosed delimiter near character ${stack.at(-1).i}.` };
  return { ok: true, note: 'Basic delimiter/string checks passed. This is not full Luau syntax validation.' };
}

export function transformLuau(source) {
  let out = '', quote = null, escaped = false, lineComment = false, pendingSpace = false, longString = null;
  const word = c => !!c && /[A-Za-z0-9_]/.test(c);
  const quoteChar = c => c === '"' || c === "'";
  const operatorChar = c => !!c && /[+*/%^#=<>~:.\-]/.test(c);
  const appendPending = next => {
    const prev = out.at(-1);
    if (!pendingSpace) return;
    if (!prev) { pendingSpace = false; return; }
    // Keep a separator where removing whitespace could merge tokens or change operators.
    if ((word(prev) && word(next)) || (word(prev) && quoteChar(next)) || (quoteChar(prev) && word(next)) ||
        (operatorChar(prev) && operatorChar(next)) || (prev === '.' && /\d/.test(next || '')) ||
        (/[\d]/.test(prev) && next === '.') || (prev === ']' && next === '[')) out += ' ';
    pendingSpace = false;
  };
  for (let i = 0; i < source.length; i++) {
    const c = source[i], n = source[i + 1];
    if (longString) {
      const closeLen = longBracketClose(source, i, longString.equals);
      if (closeLen) { out += source.slice(i, i + closeLen); i += closeLen - 1; longString = null; }
      else out += c;
      continue;
    }
    if (lineComment) { if (c === '\n' || c === '\r') { lineComment = false; pendingSpace = true; } continue; }
    if (quote) {
      out += c;
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '-' && n === '-') {
      const open = longBracketOpen(source, i + 2);
      if (open) {
        i += open.length + 1;
        const endToken = ']' + '='.repeat(open.equals) + ']';
        const end = source.indexOf(endToken, i + 1);
        if (end < 0) break;
        i = end + endToken.length - 1;
      } else { lineComment = true; i++; }
      pendingSpace = true;
      continue;
    }
    const open = longBracketOpen(source, i);
    if (open) {
      appendPending(c); longString = { equals: open.equals };
      out += source.slice(i, i + open.length); i += open.length - 1; continue;
    }
    if (quoteChar(c)) { appendPending(c); quote = c; out += c; continue; }
    if (/\s/.test(c)) { pendingSpace = true; continue; }
    appendPending(c); out += c;
  }
  return out.trim();
}
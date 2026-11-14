// Renders the live OpenAPI document into the docs page. DOM APIs only (clipboard/API text is never parsed as HTML).
const el = (tag, props = {}, ...kids) => {
  const n = Object.assign(document.createElement(tag), props);
  n.append(...kids.filter((k) => k !== null && k !== undefined));
  return n;
};

const spec = await (await fetch('/api/v1/openapi.json')).json();
const root = document.getElementById('docs-root');
const nav = document.getElementById('docs-nav');
root.replaceChildren();

const sample = (schema) => {
  if (!schema) return undefined;
  if (schema.$ref) return sample(spec.components.schemas[schema.$ref.split('/').pop()]);
  if (schema.oneOf) return sample(schema.oneOf[0]);
  if (schema.enum) return schema.enum[0];
  if (schema.type === 'object') return Object.fromEntries(Object.entries(schema.properties ?? {}).map(([k, v]) => [k, sample(v)]));
  if (schema.type === 'array') return [sample(schema.items)];
  return { string: '…', integer: 0, boolean: true }[schema.type] ?? null;
};
const json = (schema) => JSON.stringify(sample(schema), null, 2);

for (const tag of spec.tags) {
  const id = `tag-${tag.name.toLowerCase()}`;
  root.append(el('h2', { id }, tag.name));
  nav.append(el('a', { href: `#${id}` }, tag.name));
  for (const [path, ops] of Object.entries(spec.paths)) {
    for (const [verb, op] of Object.entries(ops)) {
      if (!op.tags.includes(tag.name)) continue;
      const box = el('div', { className: 'ep' }, el('header', {}, el('span', { className: `verb ${verb.toUpperCase()}`, textContent: verb.toUpperCase() }), el('span', { className: 'path', textContent: path }), el('span', { className: 'dim', textContent: op.summary })));
      const body = el('div', { className: 'body' });
      if (op.description) body.append(el('p', { textContent: op.description }));
      const rb = op.requestBody?.content?.['application/json']?.schema;
      if (rb) body.append(el('div', { textContent: 'Request body' }), el('pre', { textContent: json(rb) }));
      for (const [code, r] of Object.entries(op.responses)) {
        const schema = r.content?.['application/json']?.schema ?? (r.$ref ? null : null);
        body.append(el('div', { textContent: `${code} ${r.description ?? ''}` }));
        if (schema) body.append(el('pre', { textContent: json(schema) }));
      }
      box.append(body);
      root.append(box);
    }
  }
}

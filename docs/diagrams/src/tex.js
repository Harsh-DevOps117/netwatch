// stdin: JSON list of TeX strings -> stdout: {items:[{inner,x,y,w,h}], defs}; MathJax 4, Fira font, glyphs as paths.
const MathJax = require('@mathjax/src');
(async () => {
  await MathJax.init({
    loader: {load: ['input/tex', 'output/svg', '[tex]/textmacros', '[tex]/color', '[tex]/enclose', '[tex]/boldsymbol']},
    tex: {packages: {'[+]': ['textmacros', 'color', 'enclose', 'boldsymbol']}},
    output: {font: 'mathjax-fira', fontCache: 'global', linebreaks: {inline: false}},   // one SVG per label, never split
    startup: {typeset: false},
  });
  await MathJax.startup.output.font.loadDynamicFiles();   // every glyph range up front, so no label stops mid-way
  const adaptor = MathJax.startup.adaptor;
  const src = JSON.parse(require('fs').readFileSync(0, 'utf8'));
  const items = [];
  for (const t of src) {
    const node = await MathJax.tex2svgPromise(t, {display: false});
    const svg = adaptor.firstChild(node);
    const [x, y, w, h] = adaptor.getAttribute(svg, 'viewBox').split(' ').map(Number);
    // data-latex holds the raw TeX unescaped ('<' breaks strict XML parsers); nothing reads it
    items.push({inner: adaptor.innerHTML(svg).replace(/ data-latex="[^"]*"/g, ''), x, y, w, h});
  }
  const defs = adaptor.innerHTML(MathJax.startup.output.fontCache.getCache());
  console.log(JSON.stringify({items, defs}));
})().catch(e => { console.error(e); process.exit(1); });

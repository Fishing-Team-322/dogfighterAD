(() => {
  const style = document.createElement('link');
  style.rel = 'stylesheet';
  style.href = '/finding-presentation.css';
  document.head.appendChild(style);

  const core = document.createElement('script');
  core.src = '/certificate-services-core.js';
  core.async = false;
  core.addEventListener('load', () => {
    const presentation = document.createElement('script');
    presentation.src = '/finding-presentation.js';
    presentation.async = false;
    document.head.appendChild(presentation);
  });
  document.head.appendChild(core);
})();

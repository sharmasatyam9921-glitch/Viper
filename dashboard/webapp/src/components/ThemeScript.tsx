/**
 * Inline script that runs before React hydration to set the data-theme
 * attribute on <html>. Avoids a flash of unstyled / wrong-theme content.
 */
export function ThemeScript() {
  const code = `
    (function() {
      try {
        var stored = localStorage.getItem('viper-theme');
        var prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        var theme = stored || (prefersDark ? 'dark' : 'light');
        document.documentElement.setAttribute('data-theme', theme);
      } catch (_) {}
    })();
  `;
  return <script dangerouslySetInnerHTML={{ __html: code }} />;
}

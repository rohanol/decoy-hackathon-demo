/** Shown for any URL that is not a screen, so a typo never looks like a broken app. */

export const NotFound = () => (
  <div className="page">
    <section className="card">
      <div className="stub">
        <div className="state__title">No such screen</div>
        <div className="state__hint">Check the URL, or pick a screen from the sidebar.</div>
      </div>
    </section>
  </div>
);

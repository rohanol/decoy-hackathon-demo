/**
 * Placeholder for screens not built yet, so navigation works end to end and
 * nobody demos a dead link. Each one names its spec section and build order.
 */

export function Stub({
  title,
  specSection,
  buildOrder,
}: {
  title: string;
  specSection: string;
  buildOrder: string;
}) {
  return (
    <div className="page">
      <div className="page__head">
        <h1 className="page__title">{title}</h1>
      </div>
      <section className="card">
        <div className="stub">
          <div className="state__title">Not built yet</div>
          <div className="state__hint">
            Specified in <span className="mono">frontend/DESIGN_SPEC.md</span> {specSection}.
          </div>
          <div className="state__hint">{buildOrder}</div>
        </div>
      </section>
    </div>
  );
}







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

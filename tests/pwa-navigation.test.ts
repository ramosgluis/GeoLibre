import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { SPA_NAVIGATION_DENYLIST } from "../apps/geolibre-desktop/vite-plugins/pwa-navigation";

const isDenied = (pathname: string): boolean =>
  SPA_NAVIGATION_DENYLIST.some((pattern) => pattern.test(pathname));

describe("PWA navigation ownership", () => {
  it("leaves the complete Share namespace to the local Share server", () => {
    assert.equal(isDenied("/share"), true);
    assert.equal(isDenied("/share/"), true);
    assert.equal(isDenied("/share/settings"), true);
    assert.equal(isDenied("/share/lramos/map.geolibre.json"), true);
  });

  it("does not deny similarly named app routes", () => {
    assert.equal(isDenied("/shareholders"), false);
    assert.equal(isDenied("/project-gallery"), false);
  });
});

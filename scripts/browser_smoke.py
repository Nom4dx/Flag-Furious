"""Browser acceptance check against a running local instance (creates then deletes one case)."""

import json
from pathlib import Path
from playwright.sync_api import sync_playwright, expect
import re

out = Path("test-results")
out.mkdir(exist_ok=True)
with sync_playwright() as p:
    browser = p.chromium.launch(
        executable_path="/usr/bin/chromium",
        headless=True,
        args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
    )
    page = browser.new_page(viewport={"width": 1440, "height": 1100}, device_scale_factor=1)
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto("http://127.0.0.1:8000/")
    expect(page.locator("#health")).to_contain_text("isolamento attivo")
    page.screenshot(animations="disabled", path=str(out / "desktop-intake.png"), full_page=True)
    page.select_option("#asset-type", "json")
    page.fill("#asset-content", json.dumps({"message": "flag{browser_verified}", "samples": [1, 4, 9]}))
    page.click("#identify")
    page.wait_for_selector("#asset-section:not([hidden])")
    page.click("#run")
    expect(page).to_have_url(re.compile(r"/cases/[a-f0-9]+/analysis/[a-f0-9]+$"))
    assert not page.locator(".case-rail").is_visible()
    assert not page.locator(".intake").is_visible()
    assert page.locator("#analysis-breadcrumb").is_visible()
    expect(page.locator("#job-status")).to_have_text(re.compile("completed|partial"), timeout=60000)
    assert page.evaluate("window.scrollY") == 0
    analysis_url = page.url
    page.reload()
    expect(page.locator("#job-status")).to_have_text(re.compile("completed|partial"), timeout=30000)
    assert page.url == analysis_url
    assert page.evaluate("window.scrollY") == 0
    page.click("#back-to-cases")
    expect(page).to_have_url("http://127.0.0.1:8000/")
    assert page.locator(".case-rail").is_visible()
    assert page.locator("#case-list .case-link.active").is_visible()
    page.locator("#case-list .case-link.active").click()
    expect(page).to_have_url("http://127.0.0.1:8000/")
    assert page.locator("#case-console").is_visible()
    assert page.locator("#delete-case").is_visible()
    assert not page.locator(".intake").is_visible()
    assert not page.locator("#asset-section").is_visible()
    assert page.locator("#case-job-list .case-job-open").count() == 1
    expect(page.locator("#case-job-list .case-job-open")).to_have_text("Entra nella dashboard →")
    page.locator("#case-job-list .case-job-open").first.click()
    expect(page).to_have_url(re.compile(r"/cases/[a-f0-9]+/analysis/[a-f0-9]+$"))
    assert page.locator("#tab-summary").is_visible()
    assert page.locator("#analysis-summary .summary-lead").is_visible()
    page.click('[data-tab="graph"]')
    assert page.locator("#graph .graph-node").count() >= 4
    page.locator("#graph .graph-node").first.click()
    assert page.locator("#node-details").is_visible()
    page.locator("#graph").hover()
    before = page.locator("#graph svg > g").get_attribute("transform")
    page.mouse.wheel(0, -300)
    page.wait_for_timeout(100)
    after = page.locator("#graph svg > g").get_attribute("transform")
    assert before != after
    assert page.locator("#plugin-run-list .plugin-nav").count() >= 1
    plugin_nav = page.locator('#plugin-run-list .plugin-nav[data-plugin-id="text-inspector"]')
    if not plugin_nav.evaluate("node => node.open"):
        plugin_nav.locator("summary").click()
    plugin_nav.locator('.plugin-section-links button[data-group="overview"]').click()
    assert page.locator("#outputs .plugin-dashboard-header").is_visible()
    assert page.locator("#outputs .asset-result").count() >= 1
    assert page.locator("#outputs .asset-result[open] .data-metrics").count() >= 1
    assert not page.locator("#outputs .technical-view[open]").count()
    assert page.locator("*").count() < 5000
    expect(page).to_have_url(re.compile(r"plugin=text-inspector.*section=overview"))
    assert page.evaluate("getComputedStyle(document.body).backgroundColor") == "rgb(0, 0, 0)"
    page.evaluate("""async () => {
      const {renderStructured, renderTable}=await import('/static/js/presentation.js');
      const holder=document.createElement('div');holder.id='mapping-test';document.body.append(holder);
      holder.append(renderTable(Array.from({length:31},(_,i)=>({name:`host-${i}`,bytes:2048,offset:255,extra:{safe:'<img src=x onerror=alert(1)>'}})),[
        {field:'name',label:'Endpoint'}, {field:'bytes',label:'Traffico',format:'bytes'},
        {field:'offset',label:'Posizione',format:'hex'}]));
      holder.append(renderStructured({zero:0,enabled:false,nested:{value:'Preservato'}}));
    }""")
    fixture = page.locator("#mapping-test")
    assert fixture.locator("th").all_text_contents() == ["Endpoint", "Traffico", "Posizione", "Dettaglio"]
    assert fixture.locator("tbody tr[data-index]").count() == 25
    assert "2 KiB" in fixture.inner_text() and "0xFF" in fixture.inner_text()
    fixture.get_by_role("button", name="Successivi").click()
    assert fixture.locator("tbody tr[data-index]").count() == 6
    fixture.get_by_role("searchbox").fill("host-30")
    assert fixture.locator("tbody tr[data-index]").count() == 1
    fixture.get_by_role("button", name="Apri", exact=True).click()
    fixture.locator(".data-expanded-row summary").click()
    expect(fixture.locator(".data-expanded-row")).to_contain_text("<img src=x onerror=alert(1)>")
    assert fixture.locator("img, script").count() == 0
    assert fixture.locator(".technical-view pre").count() == 0
    fixture.locator(".technical-view summary").click()
    expect(fixture.locator(".technical-view pre")).to_contain_text('"enabled": false')
    page.evaluate("document.getElementById('mapping-test').remove()")
    page.screenshot(animations="disabled", path=str(out / "desktop-results.png"), full_page=True)
    page.click('[data-tab="flags"]')
    assert "flag{browser_verified}" in page.locator("#flags").inner_text()
    # Inject every declared chart type to catch renderer branches and malformed SVG.
    kinds = page.request.get("http://127.0.0.1:8000/api/health").json()["visualizations"]
    page.evaluate(
        """async kinds => {
      const {renderVisualization}=await import('/static/js/visualizations.js');
      const holder=document.createElement('div');holder.id='chart-test';document.body.append(holder);
      for(const type of kinds){const graph=['graph','network_graph','execution_graph','tree'].includes(type);const data=graph?{nodes:[{id:'a',label:'A',status:'completed'},{id:'b',label:'B',status:'partial'}],edges:[{source:'a',target:'b'}]}:[{x:0,y:2,value:10,before:1,after:2,timestamp:'2026-09-10',label:'A'},{x:1,y:4,value:30,before:1,after:1,timestamp:'2026-09-11',label:'B'}];renderVisualization(holder,{type,title:type,data});}
    }""",
        kinds,
    )
    assert page.locator("#chart-test svg").count() == len(kinds)
    assert not page.locator("#chart-test").evaluate("e=>e.innerHTML.includes('NaN')")
    page.evaluate("document.getElementById('chart-test').remove()")
    page.set_viewport_size({"width": 390, "height": 844})
    page.screenshot(animations="disabled", path=str(out / "mobile.png"), full_page=True)
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), (
        "Mobile horizontal overflow"
    )
    colors = page.evaluate(
        """() => [...new Set([...document.querySelectorAll('body *')].filter(e=>e.getClientRects().length).flatMap(e=>{const s=getComputedStyle(e);return [s.color,s.backgroundColor,s.borderTopColor]}))]"""
    )
    import re

    assert any(re.match(r"rgba?\((39), (214), (161)", color) for color in colors), colors
    assert not errors, errors
    page.on("dialog", lambda d: d.accept())
    page.click("#delete-case")
    expect(page.locator("#case-title")).to_have_text("Nuova indagine")
    browser.close()
print("Browser PASS: case console, transitions, graph, flags, palette engine, deletion")

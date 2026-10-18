"""Browser acceptance test for document plugin and reloadable analysis route.

The script creates and deletes its own case. It verifies separation, navigation,
scroll policy, artifacts, flag provenance, graph and refresh recovery.
"""

import re
import time

import requests
from playwright.sync_api import expect, sync_playwright


BASE = "http://127.0.0.1:8000"
API = BASE + "/api"
PDF = b'%PDF-1.7\n1 0 obj << /CreatorTool (BVAULT{browser_document}) >> endobj\n<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description CreatorTool="BVAULT{browser_document}"/></rdf:RDF></x:xmpmeta>\nstartxref\n0\n%%EOF\n'


case = requests.post(API + "/cases", json={"name": "Document UI acceptance"}, timeout=10).json()
try:
    upload = requests.post(
        API + "/assets",
        data={"case_id": case["id"]},
        files={"file": ("document.pdf", PDF)},
        timeout=30,
    ).json()["assets"][0]
    job = requests.post(
        API + "/jobs",
        json={
            "case_id": case["id"],
            "asset_ids": [upload["id"]],
            "plugin_ids": ["document-metadata-forensics"],
            "prefixes": ["BVAULT"],
            "recursive": False,
        },
        timeout=10,
    ).json()
    route = f"{BASE}/cases/{case['id']}/analysis/{job['id']}"
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path="/usr/bin/chromium",
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(route)
        expect(page.locator("#breadcrumb-case")).to_have_text("Document UI acceptance")
        expect(page.locator("#job-status")).to_have_text(re.compile("completed|partial"), timeout=30_000)
        assert page.url == route
        assert not page.locator(".case-rail").is_visible()
        assert page.locator("#plugin-run-list .plugin-nav").count() == 1
        expect(page.locator("#plugin-run-list")).to_contain_text("document-metadata-forensics")
        assert "esecuzion" not in page.locator("#plugin-run-list").inner_text().lower()
        nav = page.locator('#plugin-run-list .plugin-nav[data-plugin-id="document-metadata-forensics"]')
        if not nav.evaluate("node => node.open"):
            nav.locator("summary").click()
        page.locator(
            '#plugin-run-list .plugin-nav[data-plugin-id="document-metadata-forensics"] '
            '.plugin-section-links button[data-group="metadata"]'
        ).click()
        plugin = page.locator("#outputs")
        expect(plugin.locator(".plugin-dashboard-header")).to_contain_text("document-metadata-forensics")
        expect(plugin.locator(".dashboard-results > h3")).to_have_text("Metadata")
        assert plugin.locator(".asset-result").count() >= 1
        assert plugin.locator(".asset-result[open] .output-section").count() >= 1
        expect(page.locator("#analysis-view-title")).to_contain_text("document-metadata-forensics")
        assert page.locator("#outputs").evaluate("node => node.scrollTop") == 0
        # Polling after completion must keep a reader's position.
        page.locator("#outputs").evaluate("node => node.scrollTop = 40")
        position = page.locator("#outputs").evaluate("node => node.scrollTop")
        time.sleep(1.5)
        final_position = page.locator("#outputs").evaluate("node => node.scrollTop")
        assert abs(final_position - position) <= 8, (position, final_position)
        page.click('[data-tab="flags"]')
        expect(page.locator("#flags")).to_contain_text("BVAULT{browser_document}")
        page.locator("#flags .flag-item").first.get_by_role("button", name="Apri origine").click()
        assert page.locator("#tab-outputs").is_visible() or page.locator("#tab-graph").is_visible()
        page.click('[data-tab="artifacts"]')
        assert page.locator("#artifacts .artifact-row").count() >= 1
        page.locator("#artifacts .artifact-row").first.get_by_role("button", name="Anteprima").click()
        expect(page.locator("#detail-dialog")).to_be_visible()
        page.click("#close-dialog")
        page.click('[data-tab="graph"]')
        graph_nodes = page.locator("#graph .graph-node").count()
        assert 4 <= graph_nodes <= 50
        page.reload()
        expect(page.locator("#job-status")).to_have_text("completed", timeout=30_000)
        assert page.evaluate("window.scrollY") == 0
        page.click("#back-to-cases")
        expect(page).to_have_url(BASE + "/")
        assert page.locator(".case-rail").is_visible()
        page.locator("#case-list .case-link.active").click()
        expect(page).to_have_url(BASE + "/")
        assert page.locator("#case-console").is_visible()
        assert not page.locator(".intake").is_visible()
        assert page.locator("#case-job-list .case-job-open").count() == 1
        page.locator("#case-job-list .case-job-open").first.click()
        expect(page).to_have_url(route)
        assert not errors, errors
        browser.close()
finally:
    requests.delete(API + "/cases/" + case["id"], timeout=30)

print("Document UI PASS: route, reload, plugin isolation, scroll, flag, artifact, graph, return")

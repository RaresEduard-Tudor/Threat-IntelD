import asyncio
import base64


async def take_screenshot(url: str) -> dict:
    """
    Navigate to *url* with headless Chromium and return a viewport JPEG as a
    base64 string.  Always returns a dict with keys:
        available  – bool
        image_b64  – base64 str or None
        details    – human-readable status
    """
    try:
        from playwright.async_api import async_playwright  # lazy import

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            )
            try:
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    ignore_https_errors=True,
                )
                page = await context.new_page()
                await page.goto(url, wait_until="domcontentloaded", timeout=12_000)
                await asyncio.sleep(0.8)  # let JS settle briefly
                img_bytes = await page.screenshot(
                    type="jpeg", quality=75, full_page=False
                )
            finally:
                await browser.close()

        return {
            "available": True,
            "image_b64": base64.b64encode(img_bytes).decode(),
            "details": "Screenshot captured successfully.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "available": False,
            "image_b64": None,
            "details": f"Screenshot unavailable: {str(exc)[:120]}",
        }

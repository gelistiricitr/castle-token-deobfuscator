from playwright.sync_api import sync_playwright
import zlib

with sync_playwright() as p:
    b = p.chromium.connect_over_cdp('http://127.0.0.1:9222')
    page = b.contexts[0].new_page()
    page.goto('http://127.0.0.1:8089/index.html')
    page.wait_for_timeout(1000)
    
    res = page.evaluate('''async () => {
        const analysis = await window.runAnalysis();
        const fn = globalThis.__CIPHER_FUNC;
        const serialized = Array.from(globalThis.__SERIALIZED_BYTES || []);
        const origDeflate = Array.from(globalThis.__DEFLATE_BYTES || []);
        const dollar = window.__CAPTURED_DOLLAR;
        
        return {
            token: analysis.token,
            serializedLen: serialized.length,
            serializedFirst20: serialized.slice(0, 20),
            deflateLen: origDeflate.length,
            deflateFirst20: origDeflate.slice(0, 20),
            dollarLen: dollar ? dollar.length : 0,
            hasCipherFunc: typeof fn === 'function',
            hasPn: typeof globalThis.__PN === 'function'
        };
    }''')
    
    print('Result from browser:')
    for k, v in res.items():
        print(f'{k}: {v}')
        
    page.close()

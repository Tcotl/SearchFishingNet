#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import json
import re
import random
import time
from urllib.parse import urlparse, quote
from playwright.async_api import async_playwright
from datetime import datetime
import os

class UnifiedSearchCrawler:
    def __init__(self):
        self.results = {
            'baidu': [],
            'bing': [],
            '360': [],
            'sogou': []
        }
        self.request_count = 0
        self.success_count = 0
        self.start_time = None
        self.screenshot_dir = "."
    
    # ==================== 通用工具方法 ====================
    
    def generate_realistic_fingerprint(self):
        """生成更真实的浏览器指纹"""
        chrome_versions = ['120.0.6099.109', '120.0.6099.71', '119.0.6045.160', '119.0.6045.159']
        build_ids = ['20231205', '20231130', '20231120', '20231110']
        
        fingerprint = {
            'chrome_version': random.choice(chrome_versions),
            'build_id': random.choice(build_ids),
            'user_agent': None,
            'viewport': random.choice([
                {'width': 1920, 'height': 1080},
                {'width': 1366, 'height': 768},
                {'width': 1440, 'height': 900},
                {'width': 1536, 'height': 864},
                {'width': 1280, 'height': 720}
            ]),
            'device_scale_factor': random.choice([1, 1.25, 1.5, 2]),
            'platform': random.choice(['MacIntel', 'Win32', 'Linux x86_64']),
            'language': random.choice(['zh-CN', 'en-US', 'zh-TW']),
            'timezone': random.choice(['Asia/Shanghai', 'Asia/Hong_Kong', 'America/New_York']),
            'color_scheme': random.choice(['light', 'dark']),
            'has_touch': random.choice([True, False]),
            'is_mobile': False
        }
        
        if fingerprint['platform'] == 'MacIntel':
            fingerprint['user_agent'] = f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{fingerprint['chrome_version']} Safari/537.36"
        elif fingerprint['platform'] == 'Win32':
            fingerprint['user_agent'] = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{fingerprint['chrome_version']} Safari/537.36"
        else:
            fingerprint['user_agent'] = f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{fingerprint['chrome_version']} Safari/537.36"
        
        return fingerprint
    
    def generate_dynamic_headers(self, fingerprint, page_url="", engine=""):
        """生成动态请求头"""
        accept_combinations = [
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        ]
        
        accept_language_combinations = [
            'zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7',
            'zh-TW,zh;q=0.9,en;q=0.8,en-US;q=0.7',
            'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7'
        ]
        
        chrome_major = fingerprint['chrome_version'].split('.')[0]
        sec_ch_ua = f'"Chromium";v="{chrome_major}", "Not_A Brand";v="8", "Google Chrome";v="{chrome_major}"'
        
        # 根据搜索引擎设置不同的referer
        referers = {
            'baidu': ['https://www.baidu.com/', 'https://www.baidu.com/s'],
            'bing': ['https://cn.bing.com/', 'https://cn.bing.com/search'],
            '360': ['https://www.so.com/', 'https://www.so.com/s'],
            'sogou': ['https://www.sogou.com/', 'https://www.sogou.com/web']
        }
        
        current_referers = referers.get(engine, ['https://www.google.com/'])
        
        headers = {
            'Accept': random.choice(accept_combinations),
            'Accept-Language': random.choice(accept_language_combinations),
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Cache-Control': random.choice(['max-age=0', 'no-cache', 'must-revalidate']),
            'Sec-Ch-Ua': sec_ch_ua,
            'Sec-Ch-Ua-Mobile': '?0' if not fingerprint['is_mobile'] else '?1',
            'Sec-Ch-Ua-Platform': f'"{fingerprint["platform"].split()[0]}"',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'Referer': random.choice(current_referers),
            'Connection': random.choice(['keep-alive', 'close']),
            'DNT': random.choice(['1', '0'])
        }
        
        return headers
    
    # ==================== 浏览器设置 ====================
    
    async def setup_browser(self):
        """设置浏览器 - 无头模式"""
        playwright = await async_playwright().start()
        fingerprint = self.generate_realistic_fingerprint()
        
        launch_args = [
            '--no-sandbox',
            '--disable-dev-shm-usage',
            '--disable-web-security',
            '--disable-features=IsolateOrigins,site-per-process',
            '--disable-blink-features=AutomationControlled',
            '--disable-infobars',
            '--disable-features=VizDisplayCompositor',
            '--disable-ipc-flooding-protection',
            '--disable-background-timer-throttling',
            '--disable-renderer-backgrounding',
            '--disable-backgrounding-occluded-windows',
            '--disable-features=TranslateUI',
            '--disable-webgl',
            '--disable-webrtc-accumulating',
            '--disable-background-networking',
            '--disable-default-apps',
            '--disable-sync',
            '--metrics-recording-only',
            '--no-first-run',
            '--safebrowsing-disable-auto-update',
            '--enable-features=NetworkService',
            '--disable-field-trial-config',
            '--disable-site-isolation-trials',
        ]
        
        window_width = random.randint(1200, 1920)
        window_height = random.randint(800, 1080)
        launch_args.append(f'--window-size={window_width},{window_height}')
        
        browser = await playwright.chromium.launch(
            headless=True,
            args=launch_args,
            slow_mo=random.uniform(10, 50) if random.random() < 0.3 else 0
        )
        
        context = await browser.new_context(
            user_agent=fingerprint['user_agent'],
            viewport=fingerprint['viewport'],
            locale=fingerprint['language'],
            timezone_id=fingerprint['timezone'],
            color_scheme=fingerprint['color_scheme'],
            ignore_https_errors=True,
            device_scale_factor=fingerprint['device_scale_factor'],
            has_touch=fingerprint['has_touch'],
            is_mobile=fingerprint['is_mobile'],
            java_script_enabled=True,
            bypass_csp=False,
        )
        
        # 高级指纹伪装
        fingerprint_script = """
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        window.chrome = {
            runtime: {
                PlatformOs: { MAC: 'mac', WIN: 'win', ANDROID: 'android' },
                PlatformArch: { ARM: 'arm', X86_64: 'x86_64', ARM64: 'arm64' },
                PlatformNaclArch: { ARM: 'arm', X86_64: 'x86_64', ARM64: 'arm64' },
                RequestUpdateCheckStatus: { THROTTLED: 'throttled', NO_UPDATE: 'no_update', UPDATE_AVAILABLE: 'update_available' },
                OnInstalledReason: { INSTALL: 'install', UPDATE: 'update', CHROME_UPDATE: 'chrome_update', CHROME_RESTART: 'chrome_restart' },
                OnRestartRequiredReason: { APP_UPDATE: 'app_update', OS_UPDATE: 'os_update', PERIODIC: 'periodic' }
            }
        };
        Object.defineProperty(navigator, 'plugins', {
            get: () => [
                { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format', length: 1 },
                { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '', length: 0 },
                { name: 'Native Client', filename: 'internal-nacl-plugin', description: '', length: 0 }
            ]
        });
        Object.defineProperty(navigator, 'mimeTypes', {
            get: () => [
                { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format', enabledPlugin: {} },
                { type: 'text/pdf', suffixes: 'pdf', description: 'Portable Document Format', enabledPlugin: {} }
            ]
        });
        Object.defineProperty(navigator, 'languages', { get: () => ['zh-CN', 'zh', 'en-US', 'en'] });
        Object.defineProperty(navigator, 'language', { get: () => 'zh-CN' });
        Object.defineProperty(navigator, 'platform', { get: () => 'MacIntel' });
        Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
        Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
        Object.defineProperty(screen, 'width', { get: () => 1920 });
        Object.defineProperty(screen, 'height', { get: () => 1080 });
        Object.defineProperty(screen, 'availWidth', { get: () => 1920 });
        Object.defineProperty(screen, 'availHeight', { get: () => 1040 });
        
        const originalGetBoundingClientRect = Element.prototype.getBoundingClientRect;
        Element.prototype.getBoundingClientRect = function() {
            const rect = originalGetBoundingClientRect.call(this);
            return {
                x: rect.x + (Math.random() - 0.5) * 2,
                y: rect.y + (Math.random() - 0.5) * 2,
                width: rect.width,
                height: rect.height,
                top: rect.top + (Math.random() - 0.5) * 2,
                right: rect.right + (Math.random() - 0.5) * 2,
                bottom: rect.bottom + (Math.random() - 0.5) * 2,
                left: rect.left + (Math.random() - 0.5) * 2,
                toJSON: rect.toJSON
            };
        };
        
        ['_phantom', 'callPhantom', '_webDriver', 'domAutomation', 'domAutomationController', '_selenium', '_Selenium_IDE_Recorder', 'spynner', '_cuk', '_$', 'amd', 'require', '_cordova', 'cordova', '_native', 'native', '_Native', 'Native', 'webdriver', '_webdriver', '__nightmare', 'nightmare', '_store', '_phantomJS', 'callPhantomJS', '_seleniumIDE'].forEach(prop => {
            if (window[prop] !== undefined) delete window[prop];
            if (navigator[prop] !== undefined) delete navigator[prop];
        });
        
        if (!window.performance) window.performance = {};
        if (!window.performance.now) window.performance.now = function() { return Date.now() + Math.random() * 1000; };
        if (!navigator.getBattery) {
            navigator.getBattery = function() {
                return Promise.resolve({
                    charging: Math.random() > 0.5,
                    chargingTime: Math.floor(Math.random() * 100),
                    dischargingTime: Math.floor(Math.random() * 200),
                    level: 0.5 + Math.random() * 0.5
                });
            };
        }
        """
        
        await context.add_init_script(fingerprint_script)
        page = await context.new_page()
        
        return playwright, browser, context, page, fingerprint
    
    async def setup_request_interception(self, page, fingerprint, engine):
        """设置请求拦截器"""
        async def intercept_route(route, request):
            headers = self.generate_dynamic_headers(fingerprint, request.url, engine)
            original_headers = request.headers
            original_headers.update(headers)
            
            if random.random() < 0.2:
                await asyncio.sleep(random.uniform(0.1, 0.5))
            
            await route.continue_(headers=original_headers)
        
        await page.route('**/*', intercept_route)
    
    async def simulate_human_behavior(self, page):
        """模拟人类行为"""
        try:
            await asyncio.sleep(random.uniform(0.5, 1.5))
            
            if random.random() < 0.8:
                scrolls = random.randint(2, 4)
                for _ in range(scrolls):
                    await page.mouse.wheel(0, random.randint(50, 200))
                    await asyncio.sleep(random.uniform(0.2, 0.6))
            
            if random.random() < 0.6:
                for _ in range(random.randint(2, 4)):
                    x = random.randint(100, 800)
                    y = random.randint(100, 500)
                    await page.mouse.move(x, y)
                    await asyncio.sleep(random.uniform(0.05, 0.15))
            
            await asyncio.sleep(random.uniform(0.3, 0.8))
        except:
            pass
    
    async def take_screenshot(self, page, engine, page_num, status=""):
        """保存截图"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{engine}_page{page_num+1}_{timestamp}_{status}.png"
        
        try:
            await page.screenshot(path=filename, full_page=True)
            return filename
        except Exception as e:
            return None
    
    # ==================== 搜索引擎特定方法 ====================
    
    def get_search_url(self, engine, keyword, page_num):
        """获取搜索引擎的搜索URL"""
        encoded_keyword = quote(keyword, safe='')
        
        if engine == 'baidu':
            if page_num == 0:
                return f'https://www.baidu.com/s?wd={encoded_keyword}&ie=utf-8'
            else:
                pn = page_num * 10
                return f'https://www.baidu.com/s?wd={encoded_keyword}&ie=utf-8&pn={pn}'
        
        elif engine == 'bing':
            if page_num == 0:
                return f'https://cn.bing.com/search?q={encoded_keyword}&qs=n&FORM=BESBTB&sp=-1&lq=0'
            else:
                first = page_num * 10 + 1
                return f'https://cn.bing.com/search?q={encoded_keyword}&qs=n&FORM=BESBTB&sp=-1&lq=0&first={first}'
        
        elif engine == '360':
            if page_num == 0:
                return f'https://www.so.com/s?q={encoded_keyword}&src=srp'
            else:
                return f'https://www.so.com/s?q={encoded_keyword}&src=srp&pn={page_num+1}'
        
        elif engine == 'sogou':
            if page_num == 0:
                return f'https://www.sogou.com/web?query={encoded_keyword}'
            else:
                return f'https://www.sogou.com/web?query={encoded_keyword}&page={page_num + 1}'
        
        return None
    
    async def check_security_status(self, page, engine):
        """检查安全状态"""
        try:
            content = await page.content()
            title = await page.title()
            url = page.url
            
            # 通用验证码检测
            real_captcha_indicators = [
                'cf-turnstile-widget', 'turnstile-response', '验证码', '安全验证'
            ]
            
            # 成功指标
            success_indicators = {
                'baidu': ['搜索结果', '百度为您找到以下结果', 'c-container', 'h3.t', 'result', '#content_left'],
                'bing': ['b_algo', 'b_results', '搜索结果', 'Search results'],
                '360': ['result', 'res-list', 'res', '搜索结果'],
                'sogou': ['result', 'res', '搜索结果', '结果列表', 'vrResult']
            }
            
            # 访问限制指标
            block_indicators = ['访问频率过高', '异常访问', '流量异常', '风险提示', '系统检测', '访问受限']
            
            has_real_captcha = any(indicator in content for indicator in real_captcha_indicators)
            has_success = any(indicator in content for indicator in success_indicators.get(engine, []))
            has_block = any(indicator.lower() in content.lower() or indicator.lower() in title.lower() for indicator in block_indicators)
            
            if has_success:
                return {'has_captcha': False, 'has_block': False, 'has_success': True}
            
            if has_real_captcha:
                return {'has_captcha': True, 'has_block': False, 'has_success': False}
            
            return {'has_captcha': has_real_captcha, 'has_block': has_block, 'has_success': has_success}
        except Exception as e:
            return {'has_captcha': True, 'has_block': True, 'has_success': False}
    
    async def resolve_redirect(self, page, url, engine):
        """解析重定向链接"""
        temp_page = None
        try:
            temp_page = await page.context.new_page()
            
            await temp_page.set_extra_http_headers({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7',
            })
            
            try:
                await temp_page.goto(url, wait_until='domcontentloaded', timeout=15000)
            except:
                try:
                    await temp_page.goto(url, wait_until='domcontentloaded', timeout=20000)
                except:
                    return None
            
            try:
                await temp_page.wait_for_load_state('networkidle', timeout=3000)
            except:
                pass
            
            await asyncio.sleep(2)
            
            real_url = temp_page.url
            
            if real_url and real_url != url:
                # 排除搜索引擎域名
                lower_url = real_url.lower()
                search_domains = {
                    'baidu': ['baidu.com'],
                    'bing': ['bing.com'],
                    '360': ['so.com', '360.com'],
                    'sogou': ['sogou.com']
                }
                
                excluded_domains = search_domains.get(engine, [])
                if not any(domain in lower_url for domain in excluded_domains):
                    return real_url
            
            return None
            
        except Exception as e:
            return None
        finally:
            if temp_page:
                try:
                    await temp_page.close()
                except:
                    pass
    
    async def parse_results(self, page, engine):
        """解析搜索结果"""
        results = []
        
        try:
            await asyncio.sleep(2)
            
            content = await page.content()
            
            # 检测验证码
            captcha_indicators = ['cf-turnstile-widget', '请解决以下难题以继续', 'turnstile-response']
            if any(indicator in content for indicator in captcha_indicators):
                return []
            
            # 引擎特定的选择器
            selectors = {
                'baidu': {
                    'container': '#content_left',
                    'items': '.c-container, h3.t, .result, .result-op',
                    'title': 'h3.t a, h3 a, .t a',
                    'description': '.c-abstract, .c-span18, .c-color-gray',
                    'display_url': '.c-showurl, .c-gap-right-small, cite'
                },
                'bing': {
                    'container': '#b_results',
                    'items': 'li.b_algo, li.b_cards, .b_algo, .b_cards',
                    'title': 'h2 a, h3 a, .b_title a',
                    'description': '.b_caption p, .b_algo p, .b_searchout p',
                    'display_url': '.b_caption .b_attribution, .b_algo .b_attribution, cite'
                },
                '360': {
                    'container': '#container, .result, .res-list, .res',
                    'items': 'h3, .res-title, .res-row, .result, .c-container',
                    'title': 'h3 a, .res-title a, .res-title',
                    'description': '.res-desc, .res-content, .c-abstract',
                    'display_url': '.res-url, .c-row cite, cite'
                },
                'sogou': {
                    'container': '#main, #wrapper, .results, .vrResult, .res-list, .res',
                    'items': 'h3, .vrResult, .res-title, .res-row, .result, .c-container',
                    'title': 'h3 a, .res-title a, .res-title, .vrResult h3',
                    'description': '.res-desc, .res-content, .c-abstract, .vrResult p',
                    'display_url': '.res-url, .c-row cite, cite, .display_url'
                }
            }
            
            selector_config = selectors.get(engine, selectors['baidu'])
            
            # 查找容器
            container = await page.query_selector(selector_config['container'])
            if not container:
                container = await page.query_selector('body')
            
            if container:
                # 查找所有结果项
                all_items = await container.query_selector_all(selector_config['items'])
                
                # 如果没有找到，尝试更宽泛的查找
                if not all_items:
                    all_items = await container.query_selector_all('div:has(> h3), div:has(> a), li:has(> h3)')
                
                print(f"发现 {len(all_items)} 个搜索结果项")
                
                for item in all_items[:80]:
                    try:
                        result_data = {
                            'rank': len(results) + 1,
                            'title': None,
                            'url': None,
                            'domain': None,
                            'description': None,
                            'display_url': None,
                            'raw_html': None,
                            'element_type': None
                        }
                        
                        # 获取原始HTML
                        try:
                            result_data['raw_html'] = await item.inner_html()
                        except:
                            pass
                        
                        # 获取元素类型
                        result_data['element_type'] = await item.get_attribute('class') or 'unknown'
                        
                        # 查找标题元素
                        title_elem = None
                        for selector in selector_config['title'].split(','):
                            selector = selector.strip()
                            title_elem = await item.query_selector(selector)
                            if title_elem:
                                break
                        
                        # 如果没有找到，尝试查找任何链接
                        if not title_elem:
                            all_links = await item.query_selector_all('a[href]')
                            best_link = None
                            best_text_len = 0
                            
                            for link in all_links:
                                temp_href = await link.get_attribute('href')
                                temp_title = await link.inner_text()
                                temp_title = re.sub(r'[\n\r\s]+', ' ', temp_title).strip()
                                
                                if (temp_href and temp_title and 
                                    len(temp_title.strip()) > best_text_len and
                                    'javascript:' not in temp_href and
                                    'search?q=' not in temp_href):
                                    best_text_len = len(temp_title.strip())
                                    best_link = link
                                    result_data['url'] = temp_href
                                    result_data['title'] = temp_title
                            
                            title_elem = best_link
                        
                        # 提取标题和URL
                        if title_elem and not result_data['title']:
                            result_data['url'] = await title_elem.get_attribute('href')
                            result_data['title'] = await title_elem.inner_text()
                            result_data['title'] = re.sub(r'[\n\r\s]+', ' ', result_data['title']).strip()
                        
                        # 处理重定向
                        if result_data['url'] and result_data['title']:
                            url = result_data['url']
                            
                            # 处理相对路径
                            if url.startswith('/'):
                                if engine == 'baidu':
                                    url = f'https://www.baidu.com{url}'
                                elif engine == 'bing':
                                    url = f'https://cn.bing.com{url}'
                                elif engine == '360':
                                    url = f'https://www.so.com{url}'
                                elif engine == 'sogou':
                                    url = f'https://www.sogou.com{url}'
                                result_data['url'] = url
                            
                            # 处理重定向链接
                            redirect_patterns = {
                                'baidu': ['baidu.com/link?url=', 'baidu.com/baidu.php?url='],
                                'bing': [],  # Bing通常直接链接
                                '360': ['so.com/link'],
                                'sogou': ['sogou.com/link', 'sogou.com/web?url=']
                            }
                            
                            should_resolve = any(pattern in url for pattern in redirect_patterns.get(engine, []))
                            
                            if should_resolve:
                                print(f"  → 解析重定向: {url[:60]}...")
                                real_url = await self.resolve_redirect(page, url, engine)
                                if real_url:
                                    result_data['url'] = real_url
                                    result_data['domain'] = urlparse(real_url).netloc.replace('www.', '', 1)
                                    print(f"  ✓ 解析成功: {result_data['domain']}")
                                else:
                                    print(f"  ✗ 重定向解析失败，保留原始链接")
                                    result_data['domain'] = urlparse(url).netloc.replace('www.', '', 1)
                            else:
                                result_data['domain'] = urlparse(url).netloc.replace('www.', '', 1)
                            
                            # 查找描述
                            for selector in selector_config['description'].split(','):
                                selector = selector.strip()
                                desc_elem = await item.query_selector(selector)
                                if desc_elem:
                                    desc_text = await desc_elem.inner_text()
                                    desc_text = re.sub(r'[\n\r\s]+', ' ', desc_text).strip()
                                    if desc_text and len(desc_text) > 0:
                                        result_data['description'] = desc_text
                                        break
                            
                            # 查找显示URL
                            for selector in selector_config['display_url'].split(','):
                                selector = selector.strip()
                                display_elem = await item.query_selector(selector)
                                if display_elem:
                                    display_text = await display_elem.inner_text()
                                    display_text = re.sub(r'[\n\r\s]+', ' ', display_text).strip()
                                    if display_text and len(display_text) > 0:
                                        result_data['display_url'] = display_text
                                        break
                            
                            # 基本过滤
                            if (result_data['url'] and 
                                result_data['title'] and 
                                len(result_data['title'].strip()) > 2 and
                                'javascript:' not in result_data['url']):
                                
                                results.append(result_data)
                                print(f"  ✓ {result_data['title'][:50]}...")
                            else:
                                print(f"  ✗ 跳过无效结果: {result_data['title'] or '无标题'}")
                        
                    except Exception as e:
                        print(f"  ✗ 解析错误: {e}")
                        continue
            
            # 如果没有找到结果，尝试更宽泛的查找
            if len(results) == 0:
                all_links = await page.query_selector_all('a[href*="http"]')
                for link in all_links[:80]:
                    try:
                        href = await link.get_attribute('href')
                        title = await link.inner_text()
                        title = re.sub(r'[\n\r\s]+', ' ', title).strip()
                        
                        if href and title and len(title.strip()) > 0:
                            # 过滤搜索引擎内部链接
                            search_domains = {
                                'baidu': 'baidu.com',
                                'bing': 'bing.com',
                                '360': 'so.com',
                                'sogou': 'sogou.com'
                            }
                            
                            search_domain = search_domains.get(engine, '')
                            if search_domain not in href or 's?q=' in href:
                                domain = urlparse(href).netloc.replace('www.', '', 1)
                                if domain:
                                    results.append({
                                        'rank': len(results) + 1,
                                        'title': title,
                                        'url': href,
                                        'domain': domain,
                                        'description': None,
                                        'display_url': None,
                                        'raw_html': None,
                                        'element_type': 'link_only'
                                    })
                    except:
                        continue
                    
                    if len(results) >= 80:
                        break
            
            return results
            
        except Exception as e:
            print(f"解析异常: {e}")
            return []
    
    async def search_engine(self, page, engine, keyword, max_pages, max_results_per_engine):
        """搜索单个引擎"""
        print(f"\n{'='*60}")
        print(f"开始搜索 {engine.upper()}")
        print(f"{'='*60}")
        
        consecutive_failures = 0
        max_consecutive_failures = 3
        
        for page_num in range(max_pages):
            if len(self.results[engine]) >= max_results_per_engine:
                break
            
            if consecutive_failures >= max_consecutive_failures:
                print(f'{engine.upper()} 连续 {consecutive_failures} 次失败，停止爬取')
                break
            
            print(f'\n[{engine.upper()} 进度: {len(self.results[engine])} / {max_results_per_engine} 条]')
            
            # 获取搜索URL
            search_url = self.get_search_url(engine, keyword, page_num)
            if not search_url:
                print(f"无法生成 {engine.upper()} 的搜索URL")
                break
            
            print(f"加载: {keyword} (第{page_num+1}页)")
            print(f"URL: {search_url}")
            
            # 页面加载
            success = False
            try:
                await page.goto(search_url, wait_until='networkidle', timeout=35000)
                success = True
            except:
                try:
                    await page.goto(search_url, wait_until='domcontentloaded', timeout=30000)
                    success = True
                except:
                    print("页面加载超时")
                    await self.take_screenshot(page, engine, page_num, "timeout")
            
            if not success:
                consecutive_failures += 1
                cool_down = random.uniform(10.0, 20.0)
                print(f'冷却 {cool_down:.1f} 秒...')
                await asyncio.sleep(cool_down)
                continue
            
            # 等待随机时间
            await asyncio.sleep(random.uniform(1.0, 2.0))
            
            # 检查安全状态
            status = await self.check_security_status(page, engine)
            
            if status['has_captcha']:
                await asyncio.sleep(5)
                status = await self.check_security_status(page, engine)
                if status['has_captcha']:
                    await self.take_screenshot(page, engine, page_num, "captcha")
                    consecutive_failures += 1
                    continue
            
            if status['has_block']:
                await self.take_screenshot(page, engine, page_num, "blocked")
                consecutive_failures += 1
                continue
            
            # 模拟人类行为
            await self.simulate_human_behavior(page)
            
            # 截图
            await self.take_screenshot(page, engine, page_num, "success")
            
            # 解析结果
            page_results = await self.parse_results(page, engine)
            
            if page_results:
                self.results[engine].extend(page_results)
                self.success_count += 1
                consecutive_failures = 0
                print(f'本页获得 {len(page_results)} 个结果，累计 {len(self.results[engine])} 个')
            else:
                print('本页未解析到结果')
                consecutive_failures += 1
            
            # 页面间延迟
            if len(self.results[engine]) < max_results_per_engine and page_num < max_pages - 1:
                inter_delay = random.uniform(3.0, 6.0)
                print(f'准备下一页...等待 {inter_delay:.1f} 秒')
                await asyncio.sleep(inter_delay)
    
    async def search(self, keyword, max_pages=4, max_results_per_engine=30):
        """主搜索函数"""
        self.start_time = time.time()
        browser = None
        context = None
        
        try:
            print("初始化浏览器（无头模式）...")
            playwright, browser, context, page, fingerprint = await self.setup_browser()
            
            # 按顺序搜索四个引擎
            engines = ['baidu', 'bing', '360', 'sogou']
            
            for engine in engines:
                # 设置请求拦截器
                await self.setup_request_interception(page, fingerprint, engine)
                await asyncio.sleep(random.uniform(1.5, 2.5))
                
                # 搜索该引擎
                await self.search_engine(page, engine, keyword, max_pages, max_results_per_engine)
                
                # 引擎间延迟
                if engine != engines[-1]:
                    delay = random.uniform(5.0, 10.0)
                    print(f'\n{engine.upper()} 搜索完成，准备下一个引擎...等待 {delay:.1f} 秒')
                    await asyncio.sleep(delay)
        
        except Exception as e:
            print(f'程序异常: {e}')
            import traceback
            traceback.print_exc()
        
        finally:
            # 清理资源
            elapsed = time.time() - self.start_time if self.start_time else 0
            print(f'\n{"="*60}')
            print(f'所有引擎搜索完成')
            print(f'{"="*60}')
            print(f'总耗时: {elapsed:.1f}秒')
            print(f'请求数: {self.request_count}')
            if self.request_count > 0:
                print(f'成功率: {self.success_count}/{self.request_count} ({self.success_count/self.request_count*100:.1f}%)')
            print(f'截图保存在: {self.screenshot_dir}/')
            
            total_results = sum(len(results) for results in self.results.values())
            print(f'共收集到 {total_results} 个搜索结果:')
            for engine, results in self.results.items():
                print(f'  {engine.upper()}: {len(results)} 条')
            
            if context:
                try:
                    await context.close()
                except:
                    pass
            if browser:
                try:
                    await browser.close()
                except:
                    pass
            if playwright:
                try:
                    await playwright.stop()
                except:
                    pass
        
        return self.results
    
    def display_results(self):
        """显示结果 - 分表格输出"""
        print("\n" + "="*100)
        print("搜索结果汇总")
        print("="*100)
        
        for engine, results in self.results.items():
            if not results:
                print(f"\n{engine.upper()} - 未获取到任何搜索结果")
                continue
            
            total_count = len(results)
            
            # 表头定义
            idx_width = 6
            title_width = 40
            domain_width = 20
            url_width = 30
            
            # 构建表头和分隔线
            header = f"{'序号':^{idx_width}} | {'标题':^{title_width}} | {'域名':^{domain_width}} | {'URL':^{url_width}}"
            separator = "-" * len(header)
            
            print(f"\n{engine.upper()} 搜索结果 - 共 {total_count} 条")
            print(separator)
            print(header)
            print(separator)
            
            for i, result in enumerate(results):
                # 处理标题
                title = result['title'] if result['title'] else ""
                title = title.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
                if len(title) > title_width - 3:
                    title = title[:title_width - 3] + "..."
                else:
                    title = title.ljust(title_width)
                
                # 处理域名
                domain = result['domain'] if result['domain'] else ""
                if len(domain) > domain_width - 3:
                    domain = domain[:domain_width - 3] + "..."
                else:
                    domain = domain.ljust(domain_width)
                
                # 处理URL
                url = result['url'] if result['url'] else ""
                url_clean = url.split('?')[0]
                if len(url_clean) > url_width - 3:
                    url = url_clean[:url_width - 3] + "..."
                else:
                    url = url_clean.ljust(url_width)
                
                # 构建行数据
                row = f"{i+1:<{idx_width}} | {title} | {domain} | {url}"
                print(row)
                
                # 每5行显示分隔线
                if (i + 1) % 5 == 0 and i != total_count - 1:
                    print(separator)
            
            print(separator)
    
    def save_results(self, keyword):
        """保存结果到JSON文件"""
        if all(len(results) == 0 for results in self.results.values()):
            return None
        
        # 整理数据结构
        output_data = {
            'metadata': {
                'keyword': keyword,
                'timestamp': datetime.now().isoformat(),
                'total_results': sum(len(results) for results in self.results.values()),
                'engines': {
                    engine: {
                        'count': len(results),
                        'results': results
                    }
                    for engine, results in self.results.items()
                    if len(results) > 0
                }
            },
            'results': self.results
        }
        
        import json
        import re
        safe_name = re.sub(r'[^\w\s-]', '_', keyword)
        filename = f"unified_search_results_{safe_name}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2)
        
        return filename
    
    def save_domains_to_txt(self, keyword):
        """将所有domain输出到txt文件，每行一个域名"""
        if all(len(results) == 0 for results in self.results.values()):
            return None
        
        # 收集所有唯一的domain
        all_domains = set()
        for engine, results in self.results.items():
            for result in results:
                if result.get('domain'):
                    all_domains.add(result['domain'])
        
        if not all_domains:
            return None
        
        # 生成文件名
        import re
        safe_name = re.sub(r'[^\w\s-]', '_', keyword)
        filename = f"domains_{safe_name}.txt"
        
        # 每行一个域名，不包含其他内容
        with open(filename, 'w', encoding='utf-8') as f:
            for domain in sorted(all_domains):
                f.write(f"{domain}\n")
        
        return filename, len(all_domains)


async def main_async():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='统一搜索引擎爬虫 - 同时查询百度、Bing、360、搜狗')
    parser.add_argument('keyword', nargs='?', help='搜索关键词')
    parser.add_argument('--max-pages', type=int, default=4, help='每个引擎的最大搜索页数')
    parser.add_argument('--max-results', type=int, default=30, help='每个引擎的最大结果数量')
    args = parser.parse_args()
    
    if not args.keyword:
        args.keyword = input("请输入搜索关键词: ").strip()
    
    if not args.keyword:
        print("无效的搜索关键词")
        return
    
    spider = UnifiedSearchCrawler()
    
    try:
        results = await spider.search(
            args.keyword, 
            max_pages=args.max_pages, 
            max_results_per_engine=args.max_results
        )
        
        if any(len(r) > 0 for r in results.values()):
            spider.display_results()
            
            # 保存JSON结果
            json_filename = spider.save_results(args.keyword)
            if json_filename:
                print(f"\nJSON结果已保存到: {json_filename}")
            
            # 保存域名到txt文件
            txt_filename, domain_count = spider.save_domains_to_txt(args.keyword)
            if txt_filename:
                print(f"域名列表已保存到: {txt_filename} (共 {domain_count} 个域名)")
        else:
            print(f"\n未能获取到任何搜索结果")
            
    except KeyboardInterrupt:
        print("\n\n用户取消搜索")
    except Exception as e:
        print(f"\n程序错误: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n任务完成")

def main():
    """同步包装函数"""
    asyncio.run(main_async())

if __name__ == "__main__":
    main()

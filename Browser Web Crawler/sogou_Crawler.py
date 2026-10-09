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

class SogouCrawler:
    def __init__(self):
        self.results = []
        self.request_count = 0
        self.success_count = 0
        self.start_time = None
        self.screenshot_dir = "."  # 保存在当前目录
    
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
    
    def generate_dynamic_headers(self, fingerprint, page_url=""):
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
        
        referers = [
            'https://www.sogou.com/',
            'https://www.sogou.com/web',
            'https://www.baidu.com/',
            'https://cn.bing.com/',
            'https://duckduckgo.com/'
        ]
        
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
            'Referer': random.choice(referers),
            'Connection': random.choice(['keep-alive', 'close']),
            'DNT': random.choice(['1', '0'])
        }
        
        return headers
    
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
        
        # 无头模式运行
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
    
    async def setup_request_interception(self, page, fingerprint):
        """设置请求拦截器"""
        async def intercept_route(route, request):
            headers = self.generate_dynamic_headers(fingerprint, request.url)
            original_headers = request.headers
            original_headers.update(headers)
            
            if random.random() < 0.2:
                await asyncio.sleep(random.uniform(0.1, 0.5))
            
            await route.continue_(headers=original_headers)
        
        await page.route('**/*', intercept_route)
    
    async def simulate_human_behavior(self, page):
        """模拟人类行为"""
        try:
            # 小延迟
            await asyncio.sleep(random.uniform(0.5, 1.5))
            
            # 滚动
            if random.random() < 0.8:
                scrolls = random.randint(2, 4)
                for _ in range(scrolls):
                    await page.mouse.wheel(0, random.randint(50, 200))
                    await asyncio.sleep(random.uniform(0.2, 0.6))
            
            # 鼠标移动
            if random.random() < 0.6:
                for _ in range(random.randint(2, 4)):
                    x = random.randint(100, 800)
                    y = random.randint(100, 500)
                    await page.mouse.move(x, y)
                    await asyncio.sleep(random.uniform(0.05, 0.15))
            
            await asyncio.sleep(random.uniform(0.3, 0.8))
        except:
            pass
    
    async def take_screenshot(self, page, page_num, status=""):
        """保存截图"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"sogou_page{page_num+1}_{timestamp}_{status}.png"
        
        try:
            await page.screenshot(path=filename, full_page=True)
            return filename
        except Exception as e:
            return None
    
    async def check_security_status(self, page):
        """检查安全状态 - 优化版本"""
        try:
            content = await page.content()
            title = await page.title()
            url = page.url
            
            # 检测真正的验证码（仅检测会阻止访问的）
            real_captcha_indicators = [
                'cf-turnstile-widget',  # Cloudflare Turnstile 挑战
                'turnstile-response',   # Turnstile 响应字段
                '验证码',
                '安全验证'
            ]
            
            # 成功指标 - 页面包含搜索结果
            success_indicators = ['result', 'res', '搜索结果', '结果列表', 'vrResult']
            
            # 检测访问限制
            block_indicators = ['访问频率过高', '异常访问', '流量异常', '风险提示', '系统检测', '搜狗安全']
            
            # 严格检查真正的验证码
            has_real_captcha = any(indicator in content for indicator in real_captcha_indicators)
            
            # 检查是否有搜索结果（这是最重要的指标）
            has_success = any(indicator in content for indicator in success_indicators)
            
            # 检查访问限制
            has_block = any(indicator.lower() in content.lower() or indicator.lower() in title.lower() for indicator in block_indicators)
            
            # 如果有搜索结果，即使有软性验证码关键词也认为成功
            if has_success:
                return {
                    'has_captcha': False,
                    'has_block': False,
                    'has_success': True,
                    'title': title,
                    'url': url,
                    'content': content
                }
            
            # 如果有真正的验证码，标记为失败
            if has_real_captcha:
                return {
                    'has_captcha': True,
                    'has_block': False,
                    'has_success': False,
                    'title': title,
                    'url': url,
                    'content': content
                }
            
            return {
                'has_captcha': has_real_captcha,
                'has_block': has_block,
                'has_success': has_success,
                'title': title,
                'url': url,
                'content': content
            }
        except Exception as e:
            return {
                'has_captcha': True,
                'has_block': True,
                'has_success': False,
                'title': 'Error',
                'url': 'Error',
                'content': ''
            }
    
    async def search_page(self, page, keyword, page_num, fingerprint):
        """搜索单页"""
        self.request_count += 1
        
        try:
            encoded_keyword = quote(keyword, safe='')
            
            # 搜狗搜索URL格式
            if page_num == 0:
                full_url = f'https://www.sogou.com/web?query={encoded_keyword}'
            else:
                # 搜狗搜索的翻页参数通常是page
                full_url = f'https://www.sogou.com/web?query={encoded_keyword}&page={page_num + 1}'
            
            print(f"\n[{page_num+1}] 加载: {keyword} (第{page_num+1}页)")
            print(f"URL: {full_url}")
            
            # 页面加载
            try:
                await page.goto(full_url, wait_until='networkidle', timeout=35000)
            except:
                try:
                    await page.goto(full_url, wait_until='domcontentloaded', timeout=30000)
                except:
                    print("页面加载超时")
                    await self.take_screenshot(page, page_num, "timeout")
                    return False
            
            # 等待随机时间
            await asyncio.sleep(random.uniform(1.0, 2.0))
            
            # 检查安全状态
            status = await self.check_security_status(page)
            
            # 即使检测到验证码，也尝试继续（用户反馈说已经绕过反爬虫）
            if status['has_captcha']:
                # 额外等待，让可能的隐形验证码完成
                await asyncio.sleep(5)
                # 重新检查
                content = await page.content()
                if 'cf-turnstile' in content or '请解决以下难题以继续' in content:
                    await self.take_screenshot(page, page_num, "captcha")
                    return False
            
            if status['has_block']:
                await self.take_screenshot(page, page_num, "blocked")
                return False
            
            # 模拟人类行为
            await self.simulate_human_behavior(page)
            
            # 截图保存
            await self.take_screenshot(page, page_num, "success")
            
            self.success_count += 1
            return True
            
        except Exception as e:
            print(f"异常错误: {e}")
            try:
                await self.take_screenshot(page, page_num, "error")
            except:
                pass
            return False
    
    async def resolve_sogou_redirect(self, page, redirect_url):
        """解析搜狗搜索的重定向链接以获取真实URL"""
        temp_page = None
        try:
            # 使用上下文管理器确保页面正确关闭
            temp_page = await page.context.new_page()
            
            # 设置更真实的请求头
            await temp_page.set_extra_http_headers({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Cache-Control': 'max-age=0',
                'Upgrade-Insecure-Requests': '1',
                'Connection': 'keep-alive',
            })
            
            # 第一阶段：初始页面加载
            try:
                await temp_page.goto(redirect_url, wait_until='domcontentloaded', timeout=15000)
            except Exception as e:
                print(f'重定向页面加载失败: {e}')
                # 尝试更宽松的加载方式
                try:
                    await temp_page.goto(redirect_url, wait_until='domcontentloaded', timeout=20000)
                except:
                    return None
            
            # 第二阶段：等待网络空闲或最大3秒
            try:
                await temp_page.wait_for_load_state('networkidle', timeout=3000)
            except:
                # 网络未完全空闲，但继续执行
                pass
            
            # 第三阶段：额外等待可能的JS重定向
            await asyncio.sleep(2)
            
            # 第四阶段：检查是否有meta refresh或JS跳转
            try:
                # 检查meta refresh
                meta_refresh = await temp_page.query_selector('meta[http-equiv="refresh"]')
                if meta_refresh:
                    await asyncio.sleep(1.5)
            except:
                pass
            
            real_url = temp_page.url
            
            # 更宽松的成功判断标准
            if real_url and real_url != redirect_url:
                # 检查是否是真实的第三方网站（排除搜狗相关域名）
                lower_url = real_url.lower()
                if not any(domain in lower_url for domain in [
                    'sogou.com', 'www.sogou.com', 'm.sogou.com', 
                    'weixin.sogou.com', 'pic.sogou.com'
                ]):
                    print(f'成功解析重定向: {redirect_url[:50]}... → {real_url[:50]}...')
                    return real_url
                else:
                    print(f'重定向仍停留在搜狗: {real_url[:50]}...')
                    return None
            else:
                print(f'重定向未跳转: {real_url[:50]}...')
                return None
            
        except Exception as e:
            print(f'重定向解析异常: {e}')
            return None
        finally:
            # 确保页面正确关闭，释放资源
            if temp_page:
                try:
                    await temp_page.close()
                except:
                    pass
    
    async def parse_results(self, page):
        """解析搜狗搜索结果 - 保存所有数据，不进行任何过滤"""
        results = []
        
        try:
            # 等待页面完全加载
            await asyncio.sleep(2)
            
            # 获取页面内容
            content = await page.content()
            
            # 检测真正的验证码
            real_captcha_indicators = [
                'cf-turnstile-widget',
                '请解决以下难题以继续',
                'turnstile-response',
            ]
            
            has_real_captcha = any(indicator in content for indicator in real_captcha_indicators)
            
            if has_real_captcha:
                return []
            
            # 查找搜狗搜索结果容器 - 搜狗可能使用多种容器结构
            res_container = await page.query_selector('#main, #wrapper, .results, .vrResult, .res-list, .res')
            if not res_container:
                # 尝试更宽泛的选择器
                res_container = await page.query_selector('body')
            
            if res_container:
                # 查找搜狗搜索结果项 - 搜狗通常使用包含h3标题的容器
                # 搜狗可能的结构：.vrResult, .res-list, h3标题等
                all_items = await res_container.query_selector_all('h3, .vrResult, .res-title, .res-row, .result, .c-container')
                
                # 如果没有找到特定选择器，尝试查找所有包含链接的容器
                if not all_items:
                    all_items = await res_container.query_selector_all('div:has(> h3), div:has(> a), li:has(> h3)')
                
                # 搜狗可能使用ul列表结构
                if not all_items:
                    all_items = await res_container.query_selector_all('ul.res-list li, ul.result li, .res-list li, .vrResult')
                
                print(f"发现 {len(all_items)} 个搜索结果项")
                
                for item in all_items[:80]:  # 增加处理数量到80
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
                        
                        # 获取原始HTML（用于完整数据保存）
                        try:
                            result_data['raw_html'] = await item.inner_html()
                        except:
                            pass
                        
                        # 获取元素类型
                        result_data['element_type'] = await item.get_attribute('class') or 'unknown'
                        
                        # 方法1: 查找标题链接 - 搜狗通常使用h3或包含res-title的链接
                        title_elem = await item.query_selector('h3 a')
                        if not title_elem:
                            title_elem = await item.query_selector('.res-title a')
                        if not title_elem:
                            title_elem = await item.query_selector('.res-title')
                        if not title_elem:
                            title_elem = await item.query_selector('h3')
                        if not title_elem:
                            title_elem = await item.query_selector('.vrResult h3')
                        
                        # 方法2: 查找任何明显的标题链接
                        if not title_elem:
                            # 查找b_title或类似容器中的链接
                            title_elem = await item.query_selector('.b_title a')
                        
                        # 方法3: 查找b_caption中的链接
                        if not title_elem:
                            caption = await item.query_selector('.b_caption')
                            if caption:
                                title_elem = await caption.query_selector('a')
                        
                        # 方法4: 查找b_algo中的链接
                        if not title_elem:
                            algo = await item.query_selector('.b_algo')
                            if algo:
                                title_elem = await algo.query_selector('a')
                        
                        # 方法5: 查找任何链接，选择最长文本的作为标题
                        if not title_elem:
                            all_links = await item.query_selector_all('a[href]')
                            best_link = None
                            best_text_len = 0
                            
                            for link in all_links:
                                temp_href = await link.get_attribute('href')
                                temp_title = await link.inner_text()
                                temp_title = re.sub(r'[\n\r\s]+', ' ', temp_title).strip()
                                
                                # 选择文本最长且不是空链接的有效链接
                                if (temp_href and temp_title and 
                                    len(temp_title.strip()) > best_text_len and
                                    'javascript:' not in temp_href and
                                    'search?q=' not in temp_href):
                                    best_text_len = len(temp_title.strip())
                                    best_link = link
                                    result_data['url'] = temp_href
                                    result_data['title'] = temp_title
                            
                            title_elem = best_link
                        
                        # 如果找到标题元素，提取更多信息
                        if title_elem and not result_data['title']:
                            result_data['url'] = await title_elem.get_attribute('href')
                            result_data['title'] = await title_elem.inner_text()
                            result_data['title'] = re.sub(r'[\n\r\s]+', ' ', result_data['title']).strip()
                        
                        if result_data['url'] and result_data['title']:
                            # 处理搜狗重定向链接 - 需要先转换为完整URL
                            url = result_data['url']
                            
                            # 如果是相对路径，转换为完整URL
                            if url.startswith('/'):
                                url = f'https://www.sogou.com{url}'
                                result_data['url'] = url
                            
                            # 处理搜狗重定向链接
                            if 'sogou.com/link' in url or 'sogou.com/web?url=' in url:
                                print(f"  → 解析重定向: {url[:60]}...")
                                real_url = await self.resolve_sogou_redirect(page, url)
                                if real_url:
                                    result_data['url'] = real_url
                                    result_data['domain'] = urlparse(real_url).netloc.replace('www.', '', 1)
                                    print(f"  ✓ 解析成功: {result_data['domain']}")
                                else:
                                    print(f"  ✗ 重定向解析失败，保留原始链接")
                                    # 保留原始链接但提取域名
                                    result_data['domain'] = urlparse(url).netloc.replace('www.', '', 1)
                            else:
                                # 直接链接，提取域名
                                result_data['domain'] = urlparse(url).netloc.replace('www.', '', 1)
                            
                            # 查找描述 - 多种可能的选择器
                            description_selectors = [
                                '.res-desc',
                                '.res-content',
                                '.c-abstract',
                                '.res-row p',
                                'p.res-desc',
                                '.c-row p',
                                '.vrResult p'
                            ]
                            
                            for selector in description_selectors:
                                description_elem = await item.query_selector(selector)
                                if description_elem:
                                    desc_text = await description_elem.inner_text()
                                    desc_text = re.sub(r'[\n\r\s]+', ' ', desc_text).strip()
                                    if desc_text and len(desc_text) > 0:
                                        result_data['description'] = desc_text
                                        break
                            
                            # 查找显示URL
                            display_url_selectors = [
                                '.res-url',
                                '.c-row cite',
                                '.res-row cite',
                                'cite',
                                '.display_url'
                            ]
                            
                            for selector in display_url_selectors:
                                display_url_elem = await item.query_selector(selector)
                                if display_url_elem:
                                    display_text = await display_url_elem.inner_text()
                                    display_text = re.sub(r'[\n\r\s]+', ' ', display_text).strip()
                                    if display_text and len(display_text) > 0:
                                        result_data['display_url'] = display_text
                                        break
                            
                            # 只过滤最基本的无效数据
                            if (result_data['url'] and 
                                result_data['title'] and 
                                len(result_data['title'].strip()) > 2 and
                                'search?q=' not in result_data['url'] and
                                'javascript:' not in result_data['url']):  # 过滤搜索链接和JS链接
                                
                                results.append(result_data)
                                print(f"  ✓ {result_data['title'][:50]}...")
                            else:
                                print(f"  ✗ 跳过无效结果: {result_data['title'] or '无标题'}")
                        
                    except Exception as e:
                        print(f"  ✗ 解析错误: {e}")
                        continue
            
            # 如果没有找到结果，尝试更宽泛的查找
            if len(results) == 0:
                # 查找所有外部链接 - 不进行任何过滤
                all_links = await page.query_selector_all('a[href*="http"]')
                for link in all_links[:80]:  # 增加处理数量
                    try:
                        href = await link.get_attribute('href')
                        title = await link.inner_text()
                        title = re.sub(r'[\n\r\s]+', ' ', title).strip()
                        
                        if href and title and len(title.strip()) > 0:
                            # 只过滤搜狗内部链接和搜索链接
                            if 'sogou.com' not in href or 'search?q=' in href:
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
            
            # 不进行去重处理，返回所有结果
            return results
            
        except Exception as e:
            return []
    
    async def search(self, keyword, max_pages=4, max_results=30):
        """主搜索函数"""
        self.start_time = time.time()
        browser = None
        context = None
        
        try:
            print("初始化浏览器（无头模式）...")
            playwright, browser, context, page, fingerprint = await self.setup_browser()
            await self.setup_request_interception(page, fingerprint)
            
            await asyncio.sleep(random.uniform(1.5, 2.5))
            
            consecutive_failures = 0
            max_consecutive_failures = 3
            
            for page_num in range(max_pages):
                if len(self.results) >= max_results:
                    break
                
                if consecutive_failures >= max_consecutive_failures:
                    print(f'连续 {consecutive_failures} 次失败，停止爬取')
                    break
                
                print(f'\n进度: {len(self.results)} / {max_results} 条')
                
                # 搜索页面
                success = await self.search_page(page, keyword, page_num, fingerprint)
                
                if success:
                    consecutive_failures = 0
                    
                    # 解析结果
                    page_results = await self.parse_results(page)
                    
                    if page_results:
                        self.results.extend(page_results)
                        print(f'本页获得 {len(page_results)} 个结果，累计 {len(self.results)} 个')
                    else:
                        print('本页未解析到结果')
                    
                    # 页面间延迟
                    if len(self.results) < max_results and page_num < max_pages - 1:
                        inter_delay = random.uniform(3.0, 6.0)
                        print(f'准备下一页...等待 {inter_delay:.1f} 秒')
                        await asyncio.sleep(inter_delay)
                else:
                    consecutive_failures += 1
                    cool_down = random.uniform(10.0, 20.0)
                    print(f'冷却 {cool_down:.1f} 秒...')
                    await asyncio.sleep(cool_down)
                    
                    # 尝试刷新
                    if consecutive_failures == 1:
                        try:
                            print('尝试刷新页面...')
                            await page.reload(wait_until='domcontentloaded', timeout=25000)
                            await asyncio.sleep(2.0)
                        except:
                            pass
        
        except Exception as e:
            print(f'程序异常: {e}')
            import traceback
            traceback.print_exc()
        
        finally:
            # 清理资源
            elapsed = time.time() - self.start_time if self.start_time else 0
            print(f'\n爬取完成')
            print(f'   耗时: {elapsed:.1f}秒')
            print(f'   请求数: {self.request_count}')
            print(f'   成功率: {self.success_count}/{self.request_count} ({self.success_count/self.request_count*100:.1f}%)')
            print(f'   截图保存在: {self.screenshot_dir}/')
            print(f'   共收集到 {len(self.results)} 个搜索结果')
            
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
        
        return self.results[:max_results]
    
    def display_results(self):
        """显示结果 - 精确对齐版本，显示所有结果"""
        if not self.results:
            print('\n未获取到任何搜索结果')
            return
        
        total_count = len(self.results)
        
        # 表头定义 - 精确计算列宽
        idx_width = 6
        title_width = 52
        domain_width = 26
        url_width = 42
        
        # 构建表头和分隔线
        header = f"{'序号':^{idx_width}} | {'标题':^{title_width}} | {'域名':^{domain_width}} | {'URL':^{url_width}}"
        separator = "-" * len(header)
        
        print(f"\n搜索结果 - 共 {total_count} 条 (显示所有，无过滤)")
        print(separator)
        print(header)
        print(separator)
        
        for i, result in enumerate(self.results):
            # 处理标题 - 保留原始内容
            title = result['title']
            # 只替换换行符和制表符，保留其他内容
            title = title.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
            # 不进行额外的清理，保留原始文本
            if len(title) > title_width - 3:
                title = title[:title_width - 3] + "..."
            
            # 处理域名
            domain = result['domain']
            if len(domain) > domain_width - 3:
                domain = domain[:domain_width - 3] + "..."
            
            # 处理URL
            url = result['url']
            url_clean = url.split('?')[0]
            if len(url_clean) > url_width - 3:
                url = url_clean[:url_width - 3] + "..."
            else:
                url = url_clean
            
            # 构建行数据 - 精确对齐
            row = f"{i+1:<{idx_width}} | {title:<{title_width}} | {domain:<{domain_width}} | {url:<{url_width}}"
            print(row)
            
            # 每5行显示分隔线
            if (i + 1) % 5 == 0 and i != total_count - 1:
                print(separator)
        
        print(separator)
        print()
    
    def save_results(self, keyword):
        """保存结果"""
        if not self.results:
            return None
        
        processed_results = []
        for i, result in enumerate(self.results):
            new_result = result.copy()
            new_result['rank'] = i + 1
            processed_results.append(new_result)
        
        import json
        import re
        safe_name = re.sub(r'[^\w\s-]', '_', keyword)
        filename = f"sogou_final_results_{safe_name}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(processed_results, f, ensure_ascii=False, indent=2)
        
        return filename


async def main_async():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='搜狗搜索爬虫 - 无头模式+自动截图')
    parser.add_argument('keyword', nargs='?', help='搜索关键词')
    parser.add_argument('--max-pages', type=int, default=4, help='最大搜索页数')
    parser.add_argument('--max-results', type=int, default=30, help='最大结果数量')
    args = parser.parse_args()
    
    if not args.keyword:
        args.keyword = input("请输入搜索关键词: ").strip()
    
    if not args.keyword:
        print("无效的搜索关键词")
        return
    
    spider = SogouCrawler()
    
    try:
        results = await spider.search(
            args.keyword, 
            max_pages=args.max_pages, 
            max_results=args.max_results
        )
        
        if results:
            spider.display_results()
            filename = spider.save_results(args.keyword)
            if filename:
                print(f"\n结果已保存到: {filename}")
        else:
            print(f"\n未能获取到搜索结果")
            
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

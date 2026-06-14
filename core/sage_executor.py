"""
SageMath执行器模块
==================
通过子进程调用SageMath执行代码

功能:
- 支持本机、WSL和SageCell网页端SageMath环境
- 执行SageMath代码并返回结果
- 支持超时设置
"""

import subprocess
import json
from pathlib import Path
from typing import Optional, Tuple
from urllib import parse, request
from urllib.error import HTTPError, URLError

from core.sagemath_config import sage_config


class SageExecutor:
    """
    SageMath代码执行器
    
        通过子进程调用SageMath执行代码，支持本机、WSL和SageCell环境
    """
    
    def __init__(self):
        self.timeout = 60
    
    def is_available(self) -> bool:
        """检查SageMath是否可用"""
        return sage_config.is_configured()
    
    def get_command(self) -> Optional[str]:
        """获取SageMath执行命令"""
        return sage_config.get_executable_command()
    
    def execute(self, code: str, timeout: int = None) -> Tuple[bool, str]:
        """
        执行SageMath代码
        
        参数:
            code: SageMath代码
            timeout: 超时时间(秒)
            
        返回:
            (success, output): 是否成功和输出结果
        """
        if not self.is_available():
            return False, "SageMath未配置，请在设置中配置SageMath路径"
        
        timeout = timeout or self.timeout
        sage_type = sage_config.get_sage_type()
        
        if sage_type == 'local':
            return self._execute_local(code, timeout)
        elif sage_type == 'wsl':
            return self._execute_wsl(code, timeout)
        elif sage_type == 'online':
            return self._execute_online(code, timeout)

        return False, f"不支持的SageMath类型: {sage_type}"
    
    def _execute_local(self, code: str, timeout: int) -> Tuple[bool, str]:
        """执行本机SageMath"""
        sage_path = sage_config.get_local_path()
        
        try:
            bash_path = None
            parts = Path(sage_path).parts
            for i, part in enumerate(parts):
                if 'sagemath' in part.lower() or 'SageMath' in part:
                    sagemath_root = Path(*parts[:i+1])
                    runtime_bin = sagemath_root / 'runtime' / 'bin' / 'bash.exe'
                    if runtime_bin.exists():
                        bash_path = str(runtime_bin)
                        break
            
            if bash_path:
                sage_path_unix = self._windows_to_cygwin_path(sage_path)
                escaped_code = code.replace("'", "'\"'\"'")
                cmd = [bash_path, '-l', '-c', f"{sage_path_unix} -c '{escaped_code}'"]
            else:
                cmd = [sage_path, '-c', code]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                encoding='utf-8',
                errors='replace'
            )
            
            if result.returncode == 0:
                return True, result.stdout.strip()
            else:
                return False, f"执行错误:\n{result.stderr}"
                
        except subprocess.TimeoutExpired:
            return False, f"执行超时（{timeout}秒）"
        except FileNotFoundError:
            return False, f"找不到SageMath: {sage_path}"
        except Exception as e:
            return False, f"执行异常: {str(e)}"
    
    def _windows_to_cygwin_path(self, windows_path: str) -> str:
        """将Windows路径转换为Cygwin路径"""
        path = windows_path.replace('\\', '/')
        if ':' in path:
            drive = path[0].lower()
            path = f"/cygdrive/{drive}{path[2:]}"
        return path
    
    def _execute_wsl(self, code: str, timeout: int) -> Tuple[bool, str]:
        """执行WSL中的SageMath"""
        distro = sage_config.get_wsl_distro()
        wsl_path = sage_config.get_wsl_path()
        
        try:
            cmd = ['wsl', '-d', distro, '--', wsl_path, '-c', code]
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                encoding='utf-8',
                errors='replace'
            )
            
            if result.returncode == 0:
                return True, result.stdout.strip()
            else:
                return False, f"执行错误:\n{result.stderr}"
                
        except subprocess.TimeoutExpired:
            return False, f"执行超时（{timeout}秒）"
        except Exception as e:
            return False, f"执行异常: {str(e)}"

    def _execute_online(self, code: str, timeout: int) -> Tuple[bool, str]:
        """通过SageCell网页端服务执行SageMath。"""
        base_url = sage_config.get_online_url().strip() or 'https://sagecell.sagemath.org/'
        service_url = parse.urljoin(base_url if base_url.endswith('/') else base_url + '/', 'service')
        data = parse.urlencode({
            'code': code,
            'accepted_tos': 'true',
        }).encode('utf-8')
        req = request.Request(
            service_url,
            data=data,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Cryptoden SageCell Runner',
            },
            method='POST',
        )

        try:
            with request.urlopen(req, timeout=timeout) as response:
                body = response.read().decode('utf-8', errors='replace')
        except HTTPError as e:
            detail = e.read().decode('utf-8', errors='replace').strip()
            return self._execute_online_browser_fallbacks(code, timeout, f"HTTP {e.code}: {detail}")
        except URLError as e:
            return self._execute_online_browser_fallbacks(code, timeout, f"无法连接SageCell: {e.reason}")
        except TimeoutError:
            return self._execute_online_browser_fallbacks(code, timeout, f"SageCell执行超时（{timeout}秒）")
        except Exception as e:
            return self._execute_online_browser_fallbacks(code, timeout, f"SageCell执行异常: {str(e)}")

        try:
            result = json.loads(body)
        except json.JSONDecodeError:
            return True, body.strip()

        stdout = result.get('stdout') or result.get('text') or ''
        stderr = result.get('stderr') or result.get('error') or ''
        success = result.get('success', not stderr)
        output = stdout.strip()
        if stderr:
            output = f"{output}\n{stderr.strip()}".strip()

        return bool(success), output

    def _execute_online_browser_fallbacks(self, code: str, timeout: int, service_error: str = '') -> Tuple[bool, str]:
        """依次使用可用的无头浏览器方案执行SageCell。"""
        errors = []
        success, output = self._execute_online_playwright(code, timeout)
        if success:
            return True, output
        errors.append(f"Playwright: {output}")

        success, output = self._execute_online_selenium(code, timeout)
        if success:
            return True, output
        errors.append(f"Selenium: {output}")

        message = "SageCell在线运行失败"
        if service_error:
            message += f"\nService: {service_error}"
        return False, f"{message}\n" + "\n".join(errors)

    def _execute_online_playwright(self, code: str, timeout: int) -> Tuple[bool, str]:
        """通过Playwright无头浏览器操作SageCell页面。"""
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return False, "未安装playwright"

        base_url = sage_config.get_online_url().strip() or 'https://sagecell.sagemath.org/'

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, executable_path=p.chromium.executable_path)
                try:
                    page = browser.new_page(viewport={'width': 1280, 'height': 900})
                    page.goto(base_url, wait_until='domcontentloaded', timeout=timeout * 1000)
                    page.wait_for_selector('#cell .CodeMirror', timeout=min(timeout * 1000, 60000))
                    page.evaluate(
                        """code => {
                            const cm = document.querySelector('#cell .CodeMirror').CodeMirror;
                            cm.setValue(code);
                            cm.refresh();
                        }""",
                        code,
                    )
                    page.locator('xpath=//*[@id="cell"]/div[1]/button').click(timeout=30000)

                    output = ''
                    for _ in range(timeout):
                        page.wait_for_timeout(1000)
                        stdout = page.locator('.sagecell_stdout')
                        if stdout.count():
                            output = stdout.last.inner_text(timeout=3000).strip()
                            if output:
                                break
                        session_output = page.locator('.sagecell_sessionOutput')
                        if session_output.count():
                            output = session_output.last.inner_text(timeout=3000).strip()
                            if output:
                                break
                finally:
                    browser.close()

        except Exception as e:
            return False, f"执行异常: {str(e)}"

        if output:
            return True, output
        return False, f"执行超时（{timeout}秒）"

    def _execute_online_selenium(self, code: str, timeout: int) -> Tuple[bool, str]:
        """通过Selenium Manager无头浏览器操作SageCell页面。"""
        try:
            from selenium import webdriver
            from selenium.common.exceptions import NoSuchElementException
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support import expected_conditions as EC
            from selenium.webdriver.support.ui import WebDriverWait
        except ImportError:
            return False, "未安装selenium"

        base_url = sage_config.get_online_url().strip() or 'https://sagecell.sagemath.org/'
        driver = None

        def output_ready(active_driver):
            try:
                output_element = active_driver.find_element(By.XPATH, '//*[@id="cell"]/div[3]/div[1]/div/div[2]/pre')
            except NoSuchElementException:
                return False
            return output_element if output_element.text.strip() else False

        try:
            options = Options()
            options.add_argument('--headless=new')
            options.add_argument('--disable-gpu')
            options.add_argument('--no-sandbox')
            options.add_argument('--window-size=1280,900')

            driver = webdriver.Chrome(options=options)
            wait = WebDriverWait(driver, timeout)
            driver.get(base_url)
            wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, '#cell .CodeMirror')))
            driver.execute_script(
                """
                const cm = document.querySelector('#cell .CodeMirror').CodeMirror;
                cm.setValue(arguments[0]);
                cm.refresh();
                """,
                code,
            )
            wait.until(EC.element_to_be_clickable((By.XPATH, '//*[@id="cell"]/div[1]/button'))).click()
            output_element = wait.until(output_ready)
            return True, output_element.text.strip()
        except Exception as e:
            return False, f"执行异常: {str(e)}"
        finally:
            if driver is not None:
                driver.quit()
    
    def execute_and_parse(self, code: str, timeout: int = None) -> Tuple[bool, dict]:
        """
        执行代码并解析JSON结果
        
        参数:
            code: SageMath代码
            timeout: 超时时间
            
        返回:
            (success, result): 是否成功和解析后的结果字典
        """
        wrapped_code = f'''
import json

{code}
'''
        success, output = self.execute(wrapped_code, timeout)
        
        if not success:
            return False, {'success': False, 'error': output}
        
        try:
            lines = output.strip().split('\n')
            for line in reversed(lines):
                if line.startswith('{') and line.endswith('}'):
                    result = json.loads(line)
                    return True, result
                try:
                    result = json.loads(line)
                    if isinstance(result, dict):
                        return True, result
                except:
                    continue
            
            return True, {'success': True, 'output': output}
        except json.JSONDecodeError:
            return True, {'success': True, 'output': output}


sage_executor = SageExecutor()

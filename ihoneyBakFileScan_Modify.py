# -*- coding: UTF-8 -*-
"""
优化后的备份文件扫描器
新增功能：
1. 支持HTTP跳转检测
2. 支持HTML meta refresh跳转检测
3. 根据跳转后的URL生成增强字典
4. 智能处理跳转URL，保留目录结构，去除文件名
5. 全局增强字典：从域名站点的跳转路径中提取字典项，应用到所有站点（包括IP站点）

依赖安装：
pip install beautifulsoup4
"""

import requests
import logging
from argparse import ArgumentParser
from copy import deepcopy
from datetime import datetime
from hurry.filesize import size
from fake_headers import Headers
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin
import re
from bs4 import BeautifulSoup
import os.path

requests.packages.urllib3.disable_warnings()

logging.basicConfig(level=logging.WARNING, format="%(message)s")


def vlun(urltarget):
    pass
    # try:
    #     if proxies:
    #         r = requests.get(url=urltarget, headers=header.generate(), timeout=timeout, allow_redirects=False, stream=True, verify=False, proxies=proxies)
    #     else:
    #         r = requests.get(url=urltarget, headers=header.generate(), timeout=timeout, allow_redirects=False, stream=True, verify=False)
    #     if (r.status_code == 200) & ('html' not in r.headers.get('Content-Type')) & (
    #             'image' not in r.headers.get('Content-Type')) & ('xml' not in r.headers.get('Content-Type')) & (
    #             'text' not in r.headers.get('Content-Type')) & ('json' not in r.headers.get('Content-Type')) & (
    #             'javascript' not in r.headers.get('Content-Type')):
    #         tmp_rarsize = int(r.headers.get('Content-Length'))
    #         rarsize = str(size(tmp_rarsize))
    #         if (int(rarsize[0:-1]) > 0):
    #             logging.warning('[ success ] {}  size:{}'.format(urltarget, rarsize))
    #             with open(outputfile, 'a') as f:
    #                 try:
    #                     f.write(str(urltarget) + '  ' + 'size:' + str(rarsize) + '\n')
    #                 except:
    #                     pass
    #         else:
    #             logging.warning('[ fail ] {}'.format(urltarget))
    #     else:
    #         logging.warning('[ fail ] {}'.format(urltarget))
    # except Exception as e:
    #     logging.warning('[ fail ] {}'.format(urltarget))


def normalize_url_path(url):
    """
    标准化URL路径，去除文件名，保留目录结构
    """
    try:
        parsed = urlparse(url)
        
        # 获取路径部分
        path = parsed.path
        
        # 如果路径为空或只是根路径，直接返回
        if not path or path == '/':
            return url
        
        # 检查路径最后一部分是否像文件名
        path_parts = path.rstrip('/').split('/')
        if path_parts:
            last_part = path_parts[-1]
            
            # 判断是否为文件：包含扩展名且扩展名合理
            common_extensions = ['.html', '.htm', '.php', '.asp', '.aspx', '.jsp', '.do', 
                               '.action', '.cgi', '.pl', '.py', '.rb', '.txt', '.xml', 
                               '.json', '.css', '.js', '.pdf', '.doc', '.docx']
            
            is_file = False
            for ext in common_extensions:
                if last_part.lower().endswith(ext):
                    is_file = True
                    break
            
            # 如果包含点且不以常见目录名结尾，也认为是文件
            if '.' in last_part and not is_file:
                # 检查是否是版本号格式 (如 v1.0, api.v2 等)
                if not re.match(r'^(v\d+(\.\d+)*|api\.v\d+|.*\.v\d+)$', last_part.lower()):
                    is_file = True
            
            # 如果是文件，去除文件名，保留目录
            if is_file:
                if len(path_parts) > 1:
                    # 重构路径，去掉最后的文件名
                    new_path = '/'.join(path_parts[:-1]) + '/'
                else:
                    # 如果只有文件名，返回根目录
                    new_path = '/'
                
                # 重构完整URL
                return f"{parsed.scheme}://{parsed.netloc}{new_path}"
        
        # 确保路径以/结尾
        if not path.endswith('/'):
            path += '/'
            return f"{parsed.scheme}://{parsed.netloc}{path}"
        
        return url
        
    except Exception as e:
        print(f"[error] Failed to normalize URL path: {str(e)}")
        return url


def parse_meta_refresh(html_content, base_url):
    """
    解析HTML中的meta refresh跳转
    """
    try:
        # 使用正则表达式匹配meta refresh标签
        meta_refresh_pattern = r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\']([^"\']*)["\'][^>]*>'
        matches = re.findall(meta_refresh_pattern, html_content, re.IGNORECASE)
        
        for match in matches:
            # 解析content属性：通常格式为 "0;url=Portal/" 或 "5;url=http://example.com"
            parts = match.split(';', 1)
            if len(parts) > 1:
                url_part = parts[1].strip()
                if url_part.lower().startswith('url='):
                    redirect_url = url_part[4:].strip()
                    # 处理相对URL
                    if not redirect_url.startswith(('http://', 'https://')):
                        redirect_url = urljoin(base_url, redirect_url)
                    return redirect_url
        
        # 如果正则匹配失败，尝试使用BeautifulSoup解析
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            meta_tag = soup.find('meta', attrs={'http-equiv': re.compile(r'refresh', re.I)})
            if meta_tag and meta_tag.get('content'):
                content = meta_tag.get('content')
                parts = content.split(';', 1)
                if len(parts) > 1:
                    url_part = parts[1].strip()
                    if url_part.lower().startswith('url='):
                        redirect_url = url_part[4:].strip()
                        if not redirect_url.startswith(('http://', 'https://')):
                            redirect_url = urljoin(base_url, redirect_url)
                        return redirect_url
        except:
            pass
            
    except Exception as e:
        print(f"[error] Failed to parse meta refresh: {str(e)}")
    
    return None


def get_redirected_url(url, max_redirects=5):
    """
    获取URL的最终跳转地址，支持HTTP跳转和HTML meta refresh跳转
    智能处理跳转URL，去除文件名保留目录结构
    """
    try:
        # 第一步：检查HTTP级别的跳转
        if proxies:
            response = requests.head(url, headers=header.generate(), timeout=timeout, 
                                   allow_redirects=True, verify=False, proxies=proxies)
        else:
            response = requests.head(url, headers=header.generate(), timeout=timeout, 
                                   allow_redirects=True, verify=False)
        
        current_url = response.url
        
        # 如果HEAD请求失败或者返回的是HTML内容，使用GET请求获取完整内容
        need_content_check = False
        if (response.status_code >= 400 or 
            (response.headers.get('Content-Type', '').lower().find('text/html') != -1)):
            need_content_check = True
        
        if need_content_check:
            if proxies:
                response = requests.get(url, headers=header.generate(), timeout=timeout, 
                                      allow_redirects=True, verify=False, proxies=proxies)
            else:
                response = requests.get(url, headers=header.generate(), timeout=timeout, 
                                      allow_redirects=True, verify=False)
            
            current_url = response.url
            
            # 检查是否包含meta refresh跳转
            if (response.status_code == 200 and 
                response.headers.get('Content-Type', '').lower().find('text/html') != -1):
                
                html_content = response.text
                meta_redirect_url = parse_meta_refresh(html_content, current_url)
                
                if meta_redirect_url and meta_redirect_url != current_url:
                    print(f"[meta-redirect] {current_url} -> {meta_redirect_url}")
                    
                    # 递归检查meta跳转后的URL是否还有跳转
                    if max_redirects > 0:
                        final_url, success = get_redirected_url(meta_redirect_url, max_redirects - 1)
                        if success:
                            current_url = final_url
                    else:
                        current_url = meta_redirect_url
        
        # 标准化最终URL，去除文件名
        normalized_url = normalize_url_path(current_url)
        
        if normalized_url != url:
            print(f"[redirect] {url} -> {normalized_url}")
            if normalized_url != current_url:
                print(f"[normalized] {current_url} -> {normalized_url}")
        
        return normalized_url, True
        
    except requests.exceptions.RequestException as e:
        print(f"[error] Failed to check redirect for {url}: {str(e)}")
        return url, False


def extract_path_components(url):
    """
    从URL中提取路径组件，用于生成更精准的字典
    """
    try:
        parsed = urlparse(url)
        path = parsed.path.strip('/')
        
        if not path:
            return []
        
        # 提取路径组件
        path_parts = path.split('/')
        components = []
        
        # 添加各级路径
        for i, part in enumerate(path_parts):
            if part:
                components.append(part)
                # 添加路径组合
                if i > 0:
                    components.append('_'.join(path_parts[:i+1]))
        
        # 添加一些常见的变体
        if components:
            for comp in components[:]:  # 复制列表避免修改时的问题
                components.append(comp.replace('-', '_'))
                components.append(comp.replace('_', '-'))
                # 添加小写版本
                if comp != comp.lower():
                    components.append(comp.lower())
                # 添加大写版本
                if comp != comp.upper():
                    components.append(comp.upper())
        
        return list(set(components))
        
    except Exception as e:
        print(f"[error] Failed to extract path components: {str(e)}")
        return []


def generate_enhanced_dictionary(original_url, final_url, dic):
    """
    根据原始URL和跳转后的URL生成增强的字典
    """
    current_info_dic = deepcopy(dic)
    
    # 处理原始URL和跳转后的URL
    url_list = [original_url]
    if final_url != original_url:
        url_list.append(final_url)
    
    all_components = set()
    
    for url in url_list:
        # 解析URL获取域名部分
        if url.startswith('http://'):
            ucp = url.lstrip('http://')
        elif url.startswith('https://'):
            ucp = url.lstrip('https://')
        else:
            ucp = url
            
        # 分离域名和路径
        if '/' in ucp:
            domain_part = ucp.split('/')[0]
        else:
            domain_part = ucp
        
        # 处理端口
        if ':' in domain_part:
            domain_part = domain_part.split(':')[0]
        
        # 生成域名相关字典（保持原有逻辑）
        www1 = domain_part.split('.')
        wwwlen = len(www1)
        wwwhost = ''
        for i in range(1, wwwlen):
            wwwhost += www1[i]
        
        domainDic = [domain_part, domain_part.replace('.', ''), domain_part.replace('.', '_'), 
                    wwwhost, domain_part.split('.', 1)[-1]]
        
        if len(www1) > 1:
            domainDic.extend([
                (domain_part.split('.', 1)[1]).replace('.', '_'),
                www1[0]
            ])
            if len(www1) > 1:
                domainDic.append(www1[1])
        
        all_components.update(domainDic)
        
        # 从路径中提取组件
        path_components = extract_path_components(url)
        all_components.update(path_components)
        
        # 添加基于路径的特殊字典项
        parsed_path = urlparse(url).path.strip('/')
        if parsed_path:
            # 添加路径中的关键词
            path_keywords = parsed_path.replace('/', '_').replace('-', '_')
            all_components.add(path_keywords)
            
            # 如果路径包含常见的应用标识，添加相关字典
            common_apps = ['admin', 'portal', 'dashboard', 'console', 'manager', 'system', 
                          'login', 'auth', 'api', 'app', 'web', 'site', 'mesh', 'control',
                          'panel', 'backend', 'mgmt', 'manage']
            for app in common_apps:
                if app in parsed_path.lower():
                    all_components.add(app)
                    all_components.add(f"{app}_backup")
                    all_components.add(f"{app}_bak")
                    all_components.add(f"backup_{app}")
                    all_components.add(f"bak_{app}")
    
    # 清理并去重
    all_components = [comp for comp in all_components if comp and len(comp) > 0]
    all_components = list(set(all_components))
    
    # 为每个组件添加后缀（保持原有逻辑）
    suffixFormat = ['.zip', '.rar', '.tar.gz', '.tgz', '.tar.bz2', '.tar', '.jar', '.war', '.7z', '.bak', '.sql',
                    '.gz', '.sql.gz', '.tar.tgz', '.backup']
    
    for s in suffixFormat:
        for component in all_components:
            current_info_dic.append(component + s)
    
    return list(set(current_info_dic))


def urlcheck(target=None, ulist=None):
    if target is not None and ulist is not None:
        if target.startswith('http://') or target.startswith('https://'):
            if target.endswith('/'):
                ulist.append(target)
            else:
                ulist.append(target + '/')
        else:
            line = 'http://' + target
            if line.endswith('/'):
                ulist.append(line)
            else:
                ulist.append(line + '/')
        return ulist


def dispatcher(url_file=None, url=None, max_thread=20, dic=None, check_redirect=True):
    """
    优化后的调度器，支持跳转检测和URL标准化
    支持全局字典增强：从域名站点的跳转路径中提取字典项，应用到所有站点（包括IP站点）
    """
    urllist = []
    
    # 读取URL列表（保持原有逻辑）
    if url_file is not None and url is None:
        with open(str(url_file)) as f:
            while True:
                line = str(f.readline()).strip()
                if line:
                    urllist = urlcheck(line, urllist)
                else:
                    break
    elif url is not None and url_file is None:
        url = str(url.strip())
        urllist = urlcheck(url, urllist)
    else:
        pass

    # 创建输出文件
    with open(outputfile, 'a'):
        pass

    # 全局增强字典，用于收集从所有站点跳转中提取的路径组件
    global_enhanced_components = set()
    
    # 第一轮：收集所有跳转信息和路径组件
    redirect_info = {}
    print(f"[phase 1] Collecting redirect information from {len(urllist)} URLs...")
    
    for i, original_url in enumerate(urllist):
        print(f"[{i+1}/{len(urllist)}] Analyzing redirects for: {original_url}")
        
        # 检查跳转
        final_url = original_url
        redirect_success = True
        
        if check_redirect:
            final_url, redirect_success = get_redirected_url(original_url)
            
            # 如果检查跳转失败，使用原始URL继续
            if not redirect_success:
                final_url = original_url
        
        # 存储跳转信息
        redirect_info[original_url] = {
            'final_url': final_url,
            'redirect_success': redirect_success,
            'has_redirect': final_url != original_url
        }
        
        # 如果有跳转，从跳转路径中提取组件添加到全局字典
        if redirect_success and final_url != original_url:
            # 从原始URL和最终URL中提取路径组件
            for url in [original_url, final_url]:
                path_components = extract_path_components(url)
                global_enhanced_components.update(path_components)
                
                # 添加基于路径的特殊字典项
                parsed_path = urlparse(url).path.strip('/')
                if parsed_path:
                    # 添加路径中的关键词
                    path_keywords = parsed_path.replace('/', '_').replace('-', '_')
                    global_enhanced_components.add(path_keywords)
                    
                    # 如果路径包含常见的应用标识，添加相关字典
                    common_apps = ['admin', 'portal', 'dashboard', 'console', 'manager', 'system', 
                                  'login', 'auth', 'api', 'app', 'web', 'site', 'mesh', 'control',
                                  'panel', 'backend', 'mgmt', 'manage', 'user', 'client', 'service']
                    for app in common_apps:
                        if app in parsed_path.lower():
                            global_enhanced_components.add(app)
                            global_enhanced_components.add(f"{app}_backup")
                            global_enhanced_components.add(f"{app}_bak")
                            global_enhanced_components.add(f"backup_{app}")
                            global_enhanced_components.add(f"bak_{app}")
    
    # 生成全局增强字典
    global_enhanced_dict = []
    if global_enhanced_components:
        # 清理并去重
        global_enhanced_components = [comp for comp in global_enhanced_components if comp and len(comp) > 0]
        global_enhanced_components = list(set(global_enhanced_components))
        
        # 为每个组件添加后缀
        suffixFormat = ['.zip', '.rar', '.tar.gz', '.tgz', '.tar.bz2', '.tar', '.jar', '.war', '.7z', '.bak', '.sql',
                        '.gz', '.sql.gz', '.tar.tgz', '.backup']
        
        for s in suffixFormat:
            for component in global_enhanced_components:
                global_enhanced_dict.append(component + s)
        
        global_enhanced_dict = list(set(global_enhanced_dict))
        print(f"[global enhancement] Extracted {len(global_enhanced_components)} path components from redirects")
        print(f"[global enhancement] Generated {len(global_enhanced_dict)} additional dictionary entries")
        
        # 显示一些示例组件
        if global_enhanced_components:
            sample_components = list(global_enhanced_components)[:10]
            print(f"[global enhancement] Sample components: {', '.join(sample_components)}")
    
    # 第二轮：执行扫描
    print(f"\n[phase 2] Starting scan for {len(urllist)} URLs...")
    
    for i, original_url in enumerate(urllist):
        print(f"[{i+1}/{len(urllist)}] Processing: {original_url}")
        
        # 获取之前收集的跳转信息
        info = redirect_info[original_url]
        final_url = info['final_url']
        redirect_success = info['redirect_success']
        has_redirect = info['has_redirect']
        
        # 判断当前站点类型（用于日志）
        parsed_url = urlparse(original_url)
        is_ip_site = re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed_url.hostname or '')
        site_type = "IP site" if is_ip_site else "Domain site"
        
        # 开始生成当前站点的字典
        if check_redirect and redirect_success and has_redirect:
            # 有跳转的情况：使用增强字典生成
            current_info_dic = generate_enhanced_dictionary(original_url, final_url, dic)
            print(f"[{site_type}] Generated {len(current_info_dic)} entries based on redirect")
        else:
            # 没有跳转的情况：使用原有逻辑生成基础字典
            u = original_url
            if u.startswith('http://'):
                ucp = u.lstrip('http://')
            elif u.startswith('https://'):
                ucp = u.lstrip('https://')
            if '/' in ucp:
                ucp = ucp.split('/')[0]
            if ':' in ucp:
                ucp = ucp.split(':')[0]
                www1 = ucp.split('.')
            else:
                www1 = ucp.split('.')
            wwwlen = len(www1)
            wwwhost = ''
            for j in range(1, wwwlen):
                wwwhost += www1[j]

            current_info_dic = deepcopy(dic)
            suffixFormat = ['.zip', '.rar', '.tar.gz', '.tgz', '.tar.bz2', '.tar', '.jar', '.war', '.7z', '.bak', '.sql',
                            '.gz', '.sql.gz', '.tar.tgz', '.backup']
            domainDic = [ucp, ucp.replace('.', ''), ucp.replace('.', '_'), wwwhost, ucp.split('.', 1)[-1]]
            
            # 处理域名组件时的空值检查
            if len(www1) > 1:
                if ucp.split('.', 1)[1]:
                    domainDic.append((ucp.split('.', 1)[1]).replace('.', '_'))
                if www1[0]:
                    domainDic.append(www1[0])
                if len(www1) > 1 and www1[1]:
                    domainDic.append(www1[1])
            
            domainDic = [d for d in domainDic if d]  # 过滤空值
            domainDic = list(set(domainDic))
            
            for s in suffixFormat:
                for d in domainDic:
                    current_info_dic.extend([d + s])
            current_info_dic = list(set(current_info_dic))
            print(f"[{site_type}] Generated {len(current_info_dic)} basic dictionary entries")
        
        # 将全局增强字典合并到当前站点字典中
        if global_enhanced_dict:
            original_size = len(current_info_dic)
            current_info_dic.extend(global_enhanced_dict)
            current_info_dic = list(set(current_info_dic))  # 去重
            added_count = len(current_info_dic) - original_size
            if added_count > 0:
                print(f"[global enhancement] Added {added_count} global dictionary entries to {site_type.lower()}")
        
        print(f"[{site_type}] Total dictionary entries: {len(current_info_dic)}")
        
        # 生成检查URL列表
        check_urllist = []
        base_url = final_url if (check_redirect and redirect_success) else original_url
        
        for info_item in current_info_dic:
            check_url = str(base_url) + str(info_item)
            check_urllist.append(check_url)
            print("[add check] " + check_url)

        print(f"[info] Total URLs to check for this site: {len(check_urllist)}")

        # 多线程执行检查（保持原有逻辑）
        l = []
        p = ThreadPoolExecutor(max_thread)
        for check_url in check_urllist:
            obj = p.submit(vlun, check_url)
            l.append(obj)
        p.shutdown()
        
        print(f"[{i+1}/{len(urllist)}] Completed scanning: {original_url}\n")


if __name__ == '__main__':
    usageexample = '\n       Example: python3 optimized_backup_scanner.py -t 100 -f url.txt -o result.txt\n'
    usageexample += '                '
    usageexample += 'python3 optimized_backup_scanner.py -u https://www.example.com/ -o result.txt'

    parser = ArgumentParser(add_help=True, usage=usageexample, description='A Website Backup File Leak Scan Tool with Redirect Support.')
    parser.add_argument('-f', '--url-file', dest="url_file", help="Example: url.txt")
    parser.add_argument('-t', '--thread', dest="max_threads", nargs='?', type=int, default=1, help="Max threads")
    parser.add_argument('-u', '--url', dest='url', nargs='?', type=str, help="Example: http://www.example.com/")
    parser.add_argument('-d', '--dict-file', dest='dict_file', nargs='?', help="Example: dict.txt")
    parser.add_argument('-n', '--name', dest='prefix_name', nargs='?', help="人工猜想的文件名比如Portal,用,分割多个")
    parser.add_argument('-o', '--output-file', dest="output_file", help="Example: result.txt")
    parser.add_argument('-p', '--proxy', dest="proxy", help="Example: socks5://127.0.0.1:1080")
    parser.add_argument('--no-redirect', dest="no_redirect", action='store_true', help="禁用跳转检测")

    args = parser.parse_args()
    # Use the program default dictionary, Accurate scanning mode, Automatic dictionary generation based on domain name.
    tmp_suffixFormat = ['.zip', '.rar', '.tar.gz', '.tgz', '.tar.bz2', '.tar', '.jar', '.war', '.7z', '.bak', '.sql',
                        '.gz', '.sql.gz', '.tar.tgz']
    # 77
    tmp_info_dic = ['1', '127.0.0.1', '2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019',
                    '2020', '2021', '2022', '2023', '2024', '2025', 'admin', 'archive', 'asp', 'aspx', 'auth', 'back',
                    'backup', 'backups', 'bak', 'bbs', 'bin', 'clients', 'code', 'com', 'customers', 'dat', 'data',
                    'database', 'db', 'dump', 'engine', 'error_log', 'faisunzip', 'files', 'forum', 'home', 'html',
                    'index', 'joomla', 'js', 'jsp', 'local', 'localhost', 'master', 'media', 'members', 'my', 'mysql',
                    'new', 'old', 'orders', 'php', 'sales', 'site', 'sql', 'store', 'tar', 'test', 'user', 'users',
                    'vb', 'web', 'website', 'wordpress', 'wp', 'www', 'wwwroot', 'root', 'log']
    
    if args.prefix_name:
        if ',' in args.prefix_name:
            human_prefix = args.prefix_name.split(',')
            tmp_info_dic.extend(human_prefix)
        else:
            tmp_info_dic.append(args.prefix_name)

    info_dic = []
    for a in tmp_info_dic:
        for b in tmp_suffixFormat:
            info_dic.extend([a + b])

    global outputfile
    if (args.output_file):
        outputfile = args.output_file
    else:
        outputfile = 'result.txt'
    #add proxy
    global proxies
    if (args.proxy):
        proxies = {
            'http': args.proxy,
            'https': args.proxy
        }
    else:
        proxies = ''
    header = Headers(
        # generate any browser & os headeers
        headers=False  # don`t generate misc headers
    )

    timeout = 10

    try:
        if args.dict_file and outputfile:
            # Custom scan dictionary
            # This mode is not recommended for bulk scans. It is prone to false positives and can reduce program efficiency.
            custom_dict = list(set([i.replace("\n", "") for i in open(str(args.dict_file), "r").readlines()]))
            info_dic.extend(custom_dict)
        
        # 确定是否启用跳转检测
        check_redirect = not args.no_redirect
        
        if args.url:
            dispatcher(url=args.url, max_thread=args.max_threads, dic=info_dic, check_redirect=check_redirect)
        elif args.url_file:
            dispatcher(url_file=args.url_file, max_thread=args.max_threads, dic=info_dic, check_redirect=check_redirect)
        else:
            print("[!] Please specify a URL or URL file name")
    except Exception as e:
        print(e.args)

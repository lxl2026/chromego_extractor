# -*- coding: UTF-8 -*-
"""
Author: Linzjian666
Date: 2024-01-13 11:29:53
LastEditors: Linzjian666
LastEditTime: 2025-05-01 09:50:00
"""
import yaml
import json
import urllib.request
import logging
import geoip2.database
import socket
import base64

def process_urls(urls_file, method):
    try:
        with open(urls_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f.read().splitlines() if line.strip() and not line.strip().startswith('#')]

        for index, url in enumerate(urls):
            try:
                request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                response = urllib.request.urlopen(request, timeout=20)
                data = response.read().decode('utf-8')
                method(data, index)
            except Exception as e:
                logging.error(f"处理{url}时遇到错误: {e}")
    except Exception as e:
        logging.error(f"读取{urls_file}时遇到错误: {e}")
        return

def split_host_port(server_field):
    server_field = str(server_field).strip()
    if server_field.startswith("["):
        host, _, rest = server_field[1:].partition("]")
        port_part = rest[1:] if rest.startswith(":") else ""
        return host, port_part
    if server_field.count(":") == 1:
        return server_field.rsplit(":", 1)
    return server_field, ""

def ws_host(proxy):
    headers = (proxy.get("ws-opts") or {}).get("headers") or {}
    for key, value in headers.items():
        if str(key).lower() == "host":
            return value
    return ""

def process_clash_meta(data, index):
    try:
        content = yaml.safe_load(data)
        proxies = content.get("proxies") if isinstance(content, dict) else None
        if not proxies:
            logging.error(f"处理Clash Meta配置{index}时遇到错误: 未找到 proxies")
            return
        for i, proxy in enumerate(proxies):
            try:
                if not isinstance(proxy, dict) or not proxy.get("server") or proxy.get("port") in (None, "") or not proxy.get("type"):
                    continue
                if str(proxy.get("network", "")) == "ws":
                    key = f"{proxy['server']}:{proxy['port']}-{ws_host(proxy)}-ws"
                else:
                    key = f"{proxy['server']}:{proxy['port']}-{proxy['type']}"
                if key in servers_list:
                    continue
                location = get_physical_location(proxy["server"])
                proxy["name"] = f"{location}-{proxy['type']} | {index}-{i+1}"
                servers_list.append(key)
                extracted_proxies.append(proxy)
            except Exception as e:
                logging.error(f"处理Clash Meta配置{index}的节点{i}时遇到错误: {e}")
    except Exception as e:
        logging.error(f"处理Clash Meta配置{index}时遇到错误: {e}")
        return

def process_hysteria(data, index):
    try:
        content = json.loads(data)
        # print(content)
        auth = content['auth_str']
        server, ports = split_host_port(content['server'])
        if not ports:
            raise ValueError(f"无法解析服务器地址: {content['server']}")
        ports_slt = ports.split(',')
        server_port = int(ports_slt[0])
        fast_open = content.get('fast_open', True)
        # fast_open = True
        insecure = content['insecure']
        sni = content['server_name']
        alpn = content['alpn']
        protocol = content['protocol']
        location = get_physical_location(server)
        name = f"{location}-Hysteria | {index}-0"

        proxy = {
            "name": name,
            "type": "hysteria",
            "server": server,
            "port": server_port,
            "auth-str": auth,
            "up": 80,
            "down": 100,
            "fast-open": fast_open,
            "protocol": protocol,
            "sni": sni,
            "skip-cert-verify": insecure,
            "alpn": [alpn]
        }
        if(len(ports_slt) > 1):
            proxy["ports"] = ports_slt[1]
        if(f"{proxy['server']}:{proxy['port']}-hysteria" not in servers_list):
            extracted_proxies.append(proxy)
            servers_list.append(f"{proxy['server']}:{proxy['port']}-hysteria")
        else:
            return
    except Exception as e:
        logging.error(f"处理Hysteria配置{index}时遇到错误: {e}")
        return

def process_hysteria2(data, index):
    try:
        content = json.loads(data)
        auth = content['auth']
        server, ports = split_host_port(content['server'])
        if not ports:
            raise ValueError(f"无法解析服务器地址: {content['server']}")
        ports_slt = ports.split(',')
        server_port = int(ports_slt[0])
        insecure = content['tls']['insecure']
        sni = content['tls']['sni']
        location = get_physical_location(server)
        name = f"{location}-Hysteria2 | {index}-0"

        proxy = {
            "name": name,
            "type": "hysteria2",
            "server": server,
            "port": server_port,
            "password": auth,
            "sni": sni,
            "skip-cert-verify": insecure
        }
        if(f"{proxy['server']}:{proxy['port']}-hysteria2" not in servers_list):
            extracted_proxies.append(proxy)
            servers_list.append(f"{proxy['server']}:{proxy['port']}-hysteria2")
        else:
            return
    except Exception as e:
        logging.error(f"处理Hysteria2配置{index}时遇到错误: {e}")
        return

def transport_options(stream, network):
    if network == "ws":
        ws = stream.get("wsSettings") or {}
        return {
            "ws-opts": {
                "path": ws.get("path", ""),
                "headers": ws.get("headers") or {},
            }
        }
    if network == "grpc":
        grpc = stream.get("grpcSettings") or {}
        return {
            "grpc-opts": {
                "grpc-service-name": grpc.get("serviceName", ""),
            }
        }
    if network in ("h2", "http"):
        http = stream.get("httpSettings") or stream.get("http2Settings") or {}
        return {
            "h2-opts": {
                "path": http.get("path", "/"),
                "host": http.get("host") or [],
            }
        }
    if network == "xhttp":
        xhttp = stream.get("xhttpSettings") or {}
        xhttp_opts = {}
        if xhttp.get("path"):
            xhttp_opts["path"] = xhttp["path"]
        if xhttp.get("host"):
            xhttp_opts["host"] = xhttp["host"]
        if xhttp.get("mode"):
            xhttp_opts["mode"] = xhttp["mode"]
        return {"xhttp-opts": xhttp_opts}
    return {}

def process_xray(data, index):
    try:
        content = json.loads(data)
        pending_proxy = None
        for outbound in content.get("outbounds") or []:
            if outbound.get("protocol") in ("vmess", "vless"):
                pending_proxy = outbound
                break
        if pending_proxy is None:
            logging.error(f"处理Xray配置{index}时遇到错误: 未找到 VMess/VLESS 出站")
            return

        protocol = pending_proxy["protocol"]
        user_node = pending_proxy["settings"]["vnext"][0]
        user = user_node["users"][0]
        server = user_node["address"]
        port = user_node["port"]
        stream = pending_proxy.get("streamSettings") or {}
        raw_network = stream.get("network", "tcp")
        network = "h2" if raw_network == "http" else raw_network
        security = stream.get("security") or "none"
        if network not in ("tcp", "ws", "grpc", "h2", "xhttp"):
            logging.error(f"处理Xray配置{index}时遇到错误: 不支持的{protocol}传输协议: {raw_network}")
            return

        location = get_physical_location(server)
        proxy = {
            "name": f"{location}-{protocol} | {index}-0",
            "type": protocol,
            "server": server,
            "port": port,
            "uuid": user["id"],
            "network": network,
            "tls": security != "none",
        }
        if protocol == "vmess":
            proxy["alterId"] = user.get("alterId", 0)
            proxy["cipher"] = user.get("security", "auto")
        if user.get("flow"):
            proxy["flow"] = user["flow"]
        encryption = user.get("encryption") or ""
        if encryption and encryption != "none":
            proxy["encryption"] = encryption

        if security == "reality":
            reality = stream.get("realitySettings") or {}
            public_key = reality.get("publicKey")
            if not public_key:
                logging.error(f"处理Xray配置{index}时遇到错误: Reality 缺少 publicKey")
                return
            proxy["servername"] = reality.get("serverName", "")
            proxy["client-fingerprint"] = reality.get("fingerprint") or "chrome"
            reality_opts = {"public-key": public_key}
            if reality.get("shortId"):
                reality_opts["short-id"] = reality["shortId"]
            proxy["reality-opts"] = reality_opts
        elif security != "none":
            tls_settings = stream.get("tlsSettings") or {}
            proxy["servername"] = tls_settings.get("serverName", "")
            proxy["skip-cert-verify"] = tls_settings.get("allowInsecure", False)
            proxy["client-fingerprint"] = "chrome"
        proxy.update(transport_options(stream, raw_network))

        if f"{proxy['server']}:{proxy['port']}-{proxy['type']}" not in servers_list:
            extracted_proxies.append(proxy)
            servers_list.append(f"{proxy['server']}:{proxy['port']}-{proxy['type']}")
    except Exception as e:
        logging.error(f"处理Xray配置{index}时遇到错误: {e}")

def get_physical_location(address):
    address = str(address).strip()
    if address.startswith("["):
        address = address[1:].split("]", 1)[0]
    elif address.count(":") == 1:
        address = address.split(":", 1)[0]
    try:
        ip_address = socket.gethostbyname(address)
    except socket.gaierror:
        ip_address = address

    try:
        reader = geoip2.database.Reader("GeoLite2-City.mmdb")  # 这里的路径需要指向你自己的数据库文件
        response = reader.city(ip_address)
        country = response.country.iso_code
        # city = response.city.name
        flag_emoji = ""
        for i in range(len(country)):
            flag_emoji += chr(ord(country[i]) + ord("🇦") - ord("A"))  # 
        if(flag_emoji == "🇹🇼"):
            flag_emoji = "🇨🇳"
        return f"{flag_emoji} {country}"
    except Exception as e:
        # logging.error(f"区域代码获取失败: {e}")
        return "🏳 Unknown"
    
def normalize_for_mihomo(proxy):
    if not isinstance(proxy, dict):
        return None
    if any(proxy.get(key) in (None, "") for key in ("name", "type", "server", "port")):
        return None
    cleaned = dict(proxy)
    try:
        cleaned["port"] = int(cleaned["port"])
    except (TypeError, ValueError):
        return None
    grpc = cleaned.get("grpc-opts")
    if isinstance(grpc, dict) and "serviceName" in grpc and "grpc-service-name" not in grpc:
        grpc = dict(grpc)
        grpc["grpc-service-name"] = grpc.pop("serviceName")
        cleaned["grpc-opts"] = grpc
    if cleaned.get("tls") and cleaned.get("type") in ("vmess", "vless", "trojan") and not cleaned.get("client-fingerprint"):
        cleaned["client-fingerprint"] = "chrome"
    if cleaned.get("flow") == "":
        cleaned.pop("flow", None)
    return cleaned

def write_clash_meta_profile(template_file, output_file, extracted_proxies):
    with open(template_file, 'r', encoding='utf-8') as f:
        profile = yaml.safe_load(f)
    profile.pop("global-client-fingerprint", None)
    proxies = []
    for proxy in extracted_proxies:
        normalized = normalize_for_mihomo(proxy)
        if normalized:
            proxies.append(normalized)
    if not profile.get("proxies"):
        profile["proxies"] = proxies
    else:
        profile["proxies"].extend(proxies)
    node_names = [proxy["name"] for proxy in proxies]
    node_groups = {
        "🚀 节点选择", "♻️ 自动选择", "⚖ 负载均衡", "☁ WARP前置节点",
        "📺 巴哈姆特", "📺 哔哩哔哩", "🌏 国内媒体", "🌍 国外媒体",
        "📲 电报信息", "Ⓜ️ 微软云盘", "Ⓜ️ 微软服务", "🍎 苹果服务",
        "📢 谷歌FCM", "🤖 OpenAI", "🐟 漏网之鱼",
    }
    for group in profile.get("proxy-groups") or []:
        if group.get("name") not in node_groups:
            continue
        current = [item for item in (group.get("proxies") or []) if item]
        current.extend(node_names)
        # Mihomo treats an empty list as a missing `proxies` field.
        group["proxies"] = current or ["DIRECT"]
    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.dump(profile, f, sort_keys=False, allow_unicode=True)

def write_proxy_urls_file(output_file, proxies):
    proxy_urls = []
    for proxy in proxies:
        try:
            if(proxy['type'] == "vless"):
                name = proxy['name']
                server = proxy['server']
                port = proxy['port']
                uuid = proxy['uuid']
                tls = int(proxy.get('tls', 0))
                network = proxy['network']
                flow = proxy.get('flow', "")
                grpc_serviceName = proxy.get('grpc-opts', {}).get('grpc-service-name', "")
                ws_path = proxy.get('ws-opts', {}).get('path', "")
                try:
                    ws_headers_host = proxy.get('ws-opts', {}).get('headers', {}).get('host', "")
                except:
                    ws_headers_host = proxy.get('ws-opts', {}).get('headers', {}).get('Host', "")

                if(tls == 0):
                    proxy_url = f"vless://{uuid}@{server}:{port}?encryption=none&flow={flow}&security=none&type={network}&serviceName={grpc_serviceName}&host={ws_headers_host}&path={ws_path}#{name}"
                else:
                    sni = proxy.get('servername', "")
                    publicKey = proxy.get('reality-opts', {}).get('public-key', "")
                    short_id = proxy.get('reality-opts', {}).get('short-id', "")
                    fingerprint = proxy.get('client-fingerprint', "")
                    if(not publicKey == ""):
                        proxy_url = f"vless://{uuid}@{server}:{port}?encryption=none&flow={flow}&security=reality&sni={sni}&fp={fingerprint}&pbk={publicKey}&sid={short_id}&type={network}&serviceName={grpc_serviceName}&host={ws_headers_host}&path={ws_path}#{name}"
                    else:
                        insecure = int(proxy.get('skip-cert-verify', 0))
                        proxy_url = f"vless://{uuid}@{server}:{port}?encryption=none&flow={flow}&security=tls&sni={sni}&fp={fingerprint}&insecure={insecure}&type={network}&serviceName={grpc_serviceName}&host={ws_headers_host}&path={ws_path}#{name}" 
            
            elif(proxy['type'] == "vmess"):
                name = proxy['name']
                server = proxy['server']
                port = proxy['port']
                uuid = proxy['uuid']
                alterId = proxy['alterId']
                if(int(proxy.get('tls', 0)) == 1):
                    tls = "tls"
                else:
                    tls = ""
                sni = proxy.get('servername', "")
                network = proxy['network']
                if(network == "tcp"):
                    type = "none"
                    path = ""
                    host = ""
                elif(network == "ws"):
                    type = "none"
                    path = proxy.get('ws-opts', {}).get('path', "")
                    try:
                        host = proxy.get('ws-opts', {}).get('headers', {}).get('host', "")
                    except:
                        host = proxy.get('ws-opts', {}).get('headers', {}).get('Host', "")
                elif(network == "grpc"):
                    type = "gun"
                    path = proxy.get('grpc-opts', {}).get('grpc-service-name', "")
                    host = ""
                elif(network == "h2"):
                    type = "none"
                    path = proxy.get('h2-opts', {}).get('path', "")
                    # 获取host并将host列表转换为逗号分隔的字符串
                    host = proxy.get('h2-opts', {}).get('host', [])
                    host = ','.join(host)
                else:
                    continue
                vmess_meta = {
                    "v": "2",
                    "ps": name,
                    "add": server,
                    "port": port,
                    "id": uuid,
                    "aid": alterId,
                    "net": network,
                    "type": type,
                    "host": host,
                    "path": path,
                    "tls": tls,
                    "sni": sni,
                    "alpn": ""
                }
                # 将字典`vmess_meta`转换为 JSON 格式字符串并进行 Base64 编码
                vmess_meta = base64.b64encode(json.dumps(vmess_meta).encode('utf-8')).decode('utf-8')
                # 合并为完整的 `vmess://` URL
                proxy_url = "vmess://" + vmess_meta
            
            elif(proxy['type'] == "ss"):
                name = proxy['name']
                server = proxy['server']
                port = proxy['port']
                password = proxy['password']
                cipher = proxy['cipher']
                ss_meta = base64.b64encode(f"{cipher}:{password}").decode('utf-8')
                ss_meta = f"{ss_meta}@{server}:{port}#{name}"
                proxy_url = "ss://" + ss_meta

            
            elif(proxy['type'] == "hysteria"):
                name = proxy['name']
                server = proxy['server']
                port = proxy['port']
                protocol = proxy.get('protocol', "udp")
                insecure = int(proxy.get('skip-cert-verify', 0))
                peer = proxy.get('sni', "")
                try:
                    auth = proxy['auth-str']
                except:
                    auth = proxy['auth_str']
                upmbps = proxy.get('up', "11")
                downmbps = proxy.get('down', "55")
                alpn = proxy['alpn']
                alpn = ','.join(alpn) # 将 `alpn` 列表转换为逗号分隔的字符串
                obfs = proxy.get('obfs', "")
                proxy_url = f"hysteria://{server}:{port}/?protocol={protocol}&insecure={insecure}&peer={peer}&auth={auth}&upmbps={upmbps}&downmbps={downmbps}&alpn={alpn}&obfs={obfs}#{name}"
            
            elif(proxy['type'] == "hysteria2"):
                name = proxy['name']
                server = proxy['server']
                port = proxy['port']
                auth = proxy['password']
                sni = proxy.get('sni', "")
                insecure = int(proxy.get('skip-cert-verify', 0))
                # 如果`proxy`包含`obfs`字段，且`obfs`字段不为空
                if("obfs" in proxy and proxy['obfs'] != ""):
                    obfs = proxy['obfs']
                    obfs_password = proxy['obfs-password']
                    proxy_url = f"hysteria2://{auth}@{server}:{port}/?sni={sni}&insecure={insecure}&obfs={obfs}&obfs-password={obfs_password}#{name}"
                else:
                    proxy_url = f"hysteria2://{auth}@{server}:{port}/?sni={sni}&insecure={insecure}#{name}"
            
            elif(proxy['type'] == "tuic"):
                name = proxy['name']
                server = proxy['server']
                port = proxy['port']
                uuid = proxy['uuid']
                password = proxy.get('password', "")
                congestion_controller = proxy.get('congestion-controller', "bbr")
                udp_relay_mode = proxy.get('udp-relay-mode', "naive")
                sni = proxy.get('sni', "")
                alpn = proxy.get('alpn', [])
                alpn = ','.join(alpn) # 将 `alpn` 列表转换为逗号分隔的字符串
                allowInsecure = int(proxy.get('skip-cert-verify', 1))
                disable_sni = int(proxy.get('disable-sni', 0))
                proxy_url = f"tuic://{uuid}:{password}@{server}:{port}/?congestion_controller={congestion_controller}&udp_relay_mode={udp_relay_mode}&sni={sni}&alpn={alpn}&allow_insecure={allowInsecure}&disable_sni={disable_sni}#{name}"

            else:
                logging.error(f"处理 {proxy['name']} 时遇到问题: 不支持的协议: {proxy['type']}")
                continue

            # print(proxy_url)
            proxy_urls.append(proxy_url)
        except Exception as e:
            logging.error(f"处理 {proxy['name']} 时遇到问题: {e}")
            continue
    # 将`proxy_urls`写入`output_file`
    with open(output_file, 'w', encoding='utf-8') as f:
        for proxy_url in proxy_urls:
            f.write(proxy_url + "\n")

def write_base64_file(output_file, proxy_urls_file):
    with open(proxy_urls_file, 'r', encoding='utf-8') as f:
        proxy_urls = f.read()
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(base64.b64encode(proxy_urls.encode('utf-8')).decode('utf-8'))

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    extracted_proxies = []
    servers_list = []

    # 处理clash meta urls
    process_urls("./urls/clash_meta_urls.txt", process_clash_meta)

    # 处理hysteria urls
    process_urls("./urls/hysteria_urls.txt", process_hysteria)

    # 处理hysteria2 urls
    process_urls("./urls/hysteria2_urls.txt", process_hysteria2)

    # 处理Xray urls
    process_urls("./urls/xray_urls.txt", process_xray)

    logging.info(f"提取到 {len(extracted_proxies)} 个节点")

    # # 写入clash meta配置
    write_clash_meta_profile("./templates/clash_meta.yaml", "./outputs/clash_meta.yaml", extracted_proxies)
    write_clash_meta_profile("./templates/clash_meta_warp.yaml", "./outputs/clash_meta_warp.yaml", extracted_proxies)

    # 写入代理urls
    write_proxy_urls_file("./outputs/proxy_urls.txt", extracted_proxies)
    
    write_base64_file("./outputs/base64.txt", "./outputs/proxy_urls.txt")

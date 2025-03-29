import argparse
import argcomplete
import sys
from argparse import RawTextHelpFormatter
from os import listdir
from os.path import dirname
from os.path import join as path_join
import nxc
from nxc.paths import NXC_PATH
from nxc.loaders.protocolloader import ProtocolLoader
from nxc.helpers.logger import highlight
from nxc.helpers.args import DisplayDefaultsNotNone
from nxc.logger import nxc_logger, setup_debug_logging
import importlib.metadata


def gen_cli_args():
    setup_debug_logging()
    
    try:
        VERSION, COMMIT = importlib.metadata.version("netexec").split("+")
        DISTANCE, COMMIT = COMMIT.split(".")
    except ValueError:
        VERSION = importlib.metadata.version("netexec")
        COMMIT = ""
        DISTANCE = ""
    CODENAME = "NeedForSpeed"
    nxc_logger.debug(f"NXC VERSION: {VERSION} - {CODENAME} - {COMMIT} - {DISTANCE}")
    
    generic_parser = argparse.ArgumentParser(add_help=False, formatter_class=DisplayDefaultsNotNone)
    generic_group = generic_parser.add_argument_group("通用", "适用于所有协议的通用选项")
    generic_group.add_argument("--version", action="store_true", help="显示nxc版本")
    generic_group.add_argument("-t", "--threads", type=int, dest="threads", default=256, help="设置要使用的并发线程数")
    generic_group.add_argument("--timeout", default=None, type=int, help="每个线程的最大超时时间(秒)")
    generic_group.add_argument("--jitter", metavar="INTERVAL", type=str, help="设置每次认证之间的随机延迟")
    
    output_parser = argparse.ArgumentParser(add_help=False, formatter_class=DisplayDefaultsNotNone)
    output_group = output_parser.add_argument_group("输出", "设置详细级别和控制输出的选项")
    output_group.add_argument("--verbose", action="store_true", help="启用详细输出")
    output_group.add_argument("--debug", action="store_true", help="启用调试级别信息")
    output_group.add_argument("--no-progress", action="store_true", help="扫描期间不显示进度条")
    output_group.add_argument("--log", metavar="LOG", help="将结果导出到自定义文件")
    
    dns_parser = argparse.ArgumentParser(add_help=False, formatter_class=DisplayDefaultsNotNone)
    dns_group = dns_parser.add_argument_group("DNS")
    dns_group.add_argument("-6", dest="force_ipv6", action="store_true", help="强制启用IPv6")
    dns_group.add_argument("--dns-server", action="store", help="指定DNS服务器 (默认: 使用hosts文件和系统DNS)")
    dns_group.add_argument("--dns-tcp", action="store_true", help="DNS查询使用TCP而非UDP")
    dns_group.add_argument("--dns-timeout", action="store", type=int, default=3, help="DNS查询超时时间(秒)")
    
    parser = argparse.ArgumentParser(
        description=rf"""
     .   .
    .|   |.     _   _          _     _____
    ||   ||    | \ | |   ___  | |_  | ____| __  __   ___    ___
    \\( )//    |  \| |  / _ \ | __| |  _|   \ \/ /  / _ \  / __|
    .=[ ]=.    | |\  | |  __/ | |_  | |___   >  <  |  __/ | (__
   / /˙-˙\ \   |_| \_|  \___|  \__| |_____| /_/\_\  \___|  \___|
   ˙ \   / ˙
     ˙   ˙

    The network execution tool
    Maintained as an open source project by @NeffIsBack, @MJHallenbeck, @_zblurx
    
    For documentation and usage examples, visit: https://www.netexec.wiki/

    {highlight('Version', 'red')} : {highlight(VERSION)}
    {highlight('Codename', 'red')}: {highlight(CODENAME)}
    {highlight('Commit', 'red')}  : {highlight(COMMIT)}
    """,
        formatter_class=RawTextHelpFormatter,
        parents=[generic_parser, output_parser, dns_parser]
    )

    # we do module arg parsing here so we can reference the module_list attribute below
    module_parser = argparse.ArgumentParser(add_help=False, formatter_class=DisplayDefaultsNotNone)
    mgroup = module_parser.add_argument_group("模块", "nxc模块的选项")
    mgroup.add_argument("-M", "--module", choices=get_module_names(), action="append", metavar="MODULE", help="要使用的模块")
    mgroup.add_argument("-o", metavar="MODULE_OPTION", nargs="+", default=[], dest="module_options", help="模块选项")
    mgroup.add_argument("-L", "--list-modules", action="store_true", help="列出可用模块")
    mgroup.add_argument("--options", dest="show_module_options", action="store_true", help="显示模块选项")

    subparsers = parser.add_subparsers(title="可用协议", dest="protocol")

    std_parser = argparse.ArgumentParser(add_help=False, parents=[generic_parser, output_parser, dns_parser], formatter_class=DisplayDefaultsNotNone)
    std_parser.add_argument("target", nargs="+" if not (module_parser.parse_known_args()[0].list_modules or module_parser.parse_known_args()[0].show_module_options or generic_parser.parse_known_args()[0].version) else "*", type=str, help="目标IP、IP范围、CIDR、主机名、FQDN、包含目标列表的文件、NMap XML或.Nessus文件")
    credential_group = std_parser.add_argument_group("认证", "认证选项")
    credential_group.add_argument("-u", "--username", metavar="USERNAME", dest="username", nargs="+", default=[], help="用户名或包含用户名的文件")
    credential_group.add_argument("-p", "--password", metavar="PASSWORD", dest="password", nargs="+", default=[], help="密码或包含密码的文件")
    credential_group.add_argument("-id", metavar="CRED_ID", nargs="+", default=[], type=str, dest="cred_id", help="用于认证的数据库凭据ID")
    credential_group.add_argument("--ignore-pw-decoding", action="store_true", help="解码密码文件时忽略非UTF-8字符")
    credential_group.add_argument("--no-bruteforce", action="store_true", help="使用用户名和密码文件时不进行喷洒攻击(user1 => password1, user2 => password2)")
    credential_group.add_argument("--continue-on-success", action="store_true", help="即使认证成功也继续尝试")
    credential_group.add_argument("--gfail-limit", metavar="LIMIT", type=int, help="全局失败登录尝试的最大次数")
    credential_group.add_argument("--ufail-limit", metavar="LIMIT", type=int, help="每个用户名的失败登录尝试最大次数")
    credential_group.add_argument("--fail-limit", metavar="LIMIT", type=int, help="每个主机的失败登录尝试最大次数")

    kerberos_group = std_parser.add_argument_group("Kerberos", "Kerberos认证选项")
    kerberos_group.add_argument("-k", "--kerberos", action="store_true", help="使用Kerberos认证")
    kerberos_group.add_argument("--use-kcache", action="store_true", help="使用ccache文件中的Kerberos认证(KRB5CCNAME)")
    kerberos_group.add_argument("--aesKey", metavar="AESKEY", nargs="+", help="用于Kerberos认证的AES密钥(128或256位)")
    kerberos_group.add_argument("--kdcHost", metavar="KDCHOST", help="域控制器的FQDN。如果省略，将使用目标参数中指定的域部分(FQDN)")

    certificate_group = std_parser.add_argument_group("证书", "证书认证选项")
    certificate_group.add_argument("--pfx-cert", metavar="PFXCERT", help="使用pfx文件进行证书认证")
    certificate_group.add_argument("--pfx-base64", metavar="PFXB64", help="使用base64编码的pfx文件进行证书认证")
    certificate_group.add_argument("--pfx-pass", metavar="PFXPASS", help="pfx证书的密码")
    certificate_group.add_argument("--pem-cert", metavar="PEMCERT", help="使用PEM文件进行证书认证")
    certificate_group.add_argument("--pem-key", metavar="PEMKEY", help="PEM格式的私钥")
    
    server_group = std_parser.add_argument_group("服务器", "nxc服务器选项")
    server_group.add_argument("--server", choices={"http", "https"}, default="https", help="使用选定的服务器")
    server_group.add_argument("--server-host", type=str, default="0.0.0.0", metavar="HOST", help="服务器绑定的IP")
    server_group.add_argument("--server-port", metavar="PORT", type=int, help="在指定端口上启动服务器")
    server_group.add_argument("--connectback-host", type=str, metavar="CHOST", help="远程系统连接回的IP")    

    p_loader = ProtocolLoader()
    protocols = p_loader.get_protocols()

    try:
        for protocol in protocols:
            protocol_object = p_loader.load_protocol(protocols[protocol]["argspath"])
            subparsers = protocol_object.proto_args(subparsers, [std_parser, module_parser])
    except Exception as e:
        nxc_logger.exception(f"Error loading proto_args from proto_args.py file in protocol folder: {protocol} - {e}")

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if args.version:
        print(f"{VERSION} - {CODENAME} - {COMMIT} - {DISTANCE}")
        sys.exit(1)

    # Multiply output_tries by 10 to enable more fine granural control, see exec methods
    if hasattr(args, "get_output_tries"):
        args.get_output_tries = args.get_output_tries * 10

    return args


def get_module_names():
    """Get module names without initializing them"""
    modules = []
    modules_paths = [
        path_join(dirname(nxc.__file__), "modules"),
        path_join(NXC_PATH, "modules"),
    ]

    for path in modules_paths:
        modules.extend([module[:-3] for module in listdir(path) if module[-3:] == ".py" and module != "example_module.py"])
    return sorted(modules, key=str.casefold)

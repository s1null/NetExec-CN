from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    winrm_parser = parser.add_parser("winrm", help="使用WinRM协议攻击目标", parents=parents, formatter_class=DisplayDefaultsNotNone)
    winrm_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NTLM哈希或包含NTLM哈希的文件")
    winrm_parser.add_argument("--port", nargs="+", default=["5985", "5986"], help="WinRM端口 - 格式：'http端口 https端口'(空格分隔)或'单一端口'(提供单一端口时http和https将使用相同端口)")
    winrm_parser.add_argument("--check-proto", nargs="+", default=["http", "https"], help="选择要检查的协议 - 格式：'http https'(空格分隔)或'单一协议'")
    winrm_parser.add_argument("--laps", dest="laps", metavar="LAPS", type=str, help="LAPS认证", nargs="?", const="administrator")
    winrm_parser.add_argument("--http-timeout", dest="http_timeout", type=int, default=10, help="WinRM连接的HTTP超时")

    dgroup = winrm_parser.add_mutually_exclusive_group()
    dgroup.add_argument("-d", metavar="DOMAIN", dest="domain", type=str, default=None, help="要认证的域")
    dgroup.add_argument("--local-auth", action="store_true", help="在每个目标上进行本地认证")

    cgroup = winrm_parser.add_argument_group("凭据收集", "收集凭据的选项")
    cgroup.add_argument("--dump-method", action="store", default="cmd", choices={"cmd", "powershell"}, help="选择哈希转储中的shell类型")
    cgroup.add_argument("--sam", action="store_true", help="从目标系统转储SAM哈希")
    cgroup.add_argument("--lsa", action="store_true", help="从目标系统转储LSA密钥")

    cgroup = winrm_parser.add_argument_group("命令执行", "执行命令的选项")
    cgroup.add_argument("--codec", default="utf-8", help="设置目标输出使用的编码（codec）。如果检测到错误，在目标上运行chcp.com并使用https://docs.python.org/3/library/codecs.html#standard-encodings映射结果，然后使用--codec和相应的编码再次执行")
    cgroup.add_argument("--no-output", action="store_true", help="不获取命令输出")
    cgroup.add_argument("-x", metavar="COMMAND", dest="execute", help="执行指定的命令")
    cgroup.add_argument("-X", metavar="PS_COMMAND", dest="ps_execute", help="执行指定的PowerShell命令")

    return parser

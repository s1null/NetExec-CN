def proto_args(parser, parents):
    wmi_parser = parser.add_parser("wmi", help="使用WMI协议攻击目标", conflict_handler="resolve", parents=parents)
    wmi_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NTLM哈希或包含NTLM哈希的文件")
    wmi_parser.add_argument("--port", type=int, choices={135}, default=135, help="WMI端口（默认：135）")
    wmi_parser.add_argument("--rpc-timeout", help="RPC/DCOM(WMI)连接超时，默认%(default)s秒", type=int, default=2)

    # For domain options
    dgroup = wmi_parser.add_mutually_exclusive_group()
    dgroup.add_argument("-d", metavar="DOMAIN", dest="domain", default=None, type=str, help="要认证的域")
    dgroup.add_argument("--local-auth", action="store_true", help="在每个目标上进行本地认证")

    egroup = wmi_parser.add_argument_group("映射/枚举", "映射/枚举的选项")
    egroup.add_argument("--wmi", metavar="QUERY", dest="wmi", type=str, help="执行指定的WMI查询")
    egroup.add_argument("--wmi-namespace", metavar="NAMESPACE", type=str, default="root\\cimv2", help="WMI命名空间（默认：root\\cimv2）")

    cgroup = wmi_parser.add_argument_group("命令执行", "执行命令的选项")
    cgroup.add_argument("--no-output", action="store_true", help="不获取命令输出")
    cgroup.add_argument("-x", metavar="COMMAND", dest="execute", type=str, help="创建新的cmd进程并执行指定命令并获取输出")
    cgroup.add_argument("--exec-method", choices={"wmiexec", "wmiexec-event"}, default="wmiexec", help="执行命令的方法（默认：wmiexec）。[wmiexec (win32_process + StdRegProv)]：通过注册表获取命令结果而不使用SMB连接。[wmiexec-event (T1546.003)]：此方法不太稳定，强烈建议在单台主机上使用，在多台主机上使用可能会崩溃（如果崩溃请重试）。")
    cgroup.add_argument("--exec-timeout", default=5, metavar="exec_timeout", dest="exec_timeout", type=int, help="执行命令时设置超时（秒），建议最小5秒。默认：%(default)s")
    cgroup.add_argument("--codec", default="utf-8", help="设置目标输出使用的编码（默认：utf-8）。如果检测到错误，在目标上运行chcp.com并使用https://docs.python.org/3/library/codecs.html#standard-encodings映射结果，然后使用--codec和相应的编码再次执行")
    return parser


def get_conditional_action(base_action):
    class ConditionalAction(base_action):
        def __init__(self, option_strings, dest, **kwargs):
            x = kwargs.pop("make_required", [])
            super().__init__(option_strings, dest, **kwargs)
            self.make_required = x

        def __call__(self, parser, namespace, values, option_string=None):
            for x in self.make_required:
                x.required = True
            super().__call__(parser, namespace, values, option_string)

    return ConditionalAction

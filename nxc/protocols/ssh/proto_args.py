from argparse import _StoreAction
from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    ssh_parser = parser.add_parser("ssh", help="使用SSH协议攻击目标", parents=parents, formatter_class=DisplayDefaultsNotNone)
    ssh_parser.add_argument("--key-file", type=str, help="使用指定的私钥进行认证。将密码参数视为密钥的口令")
    ssh_parser.add_argument("--port", type=int, default=22, help="SSH端口")
    ssh_parser.add_argument("--ssh-timeout", help="SSH连接超时", type=int, default=15)
    sudo_check_arg = ssh_parser.add_argument("--sudo-check", action="store_true", help="使用sudo检查用户权限")
    sudo_check_method_arg = ssh_parser.add_argument("--sudo-check-method", action=get_conditional_action(_StoreAction), make_required=[], choices={"sudo-stdin", "mkfifo"}, default="sudo-stdin", help="执行sudo检查的方法（mkfifo不稳定，如果失败可能需要再次执行）")
    ssh_parser.add_argument("--get-output-tries", type=int, default=5, help="sudo命令尝试获取结果的次数")
    sudo_check_method_arg.make_required.append(sudo_check_arg)

    files_group = ssh_parser.add_argument_group("文件", "远程文件交互选项")
    files_group.add_argument("--put-file", action="append", nargs=2, metavar="FILE", help="将本地文件放入远程目标，例如：whoami.txt /tmp/whoami.txt")
    files_group.add_argument("--get-file", action="append", nargs=2, metavar="FILE", help="获取远程文件，例如：/tmp/whoami.txt whoami.txt")

    cgroup = ssh_parser.add_argument_group("命令执行", "执行命令的选项")
    cgroup.add_argument("--codec", default="utf-8", help="设置目标输出使用的编码（codec）。如果检测到错误，在目标上运行chcp.com，使用https://docs.python.org/3/library/codecs.html#standard-encodings映射结果，然后使用--codec和相应的编码再次执行")
    cgroup.add_argument("--no-output", action="store_true", help="不获取命令输出")
    cgroup.add_argument("-x", metavar="COMMAND", dest="execute", help="执行指定的命令")

    return parser

def get_conditional_action(baseAction):
    class ConditionalAction(baseAction):
        def __init__(self, option_strings, dest, **kwargs):
            x = kwargs.pop("make_required", [])
            super().__init__(option_strings, dest, **kwargs)
            self.make_required = x

        def __call__(self, parser, namespace, values, option_string=None):
            for x in self.make_required:
                x.required = True
            super().__call__(parser, namespace, values, option_string)

    return ConditionalAction
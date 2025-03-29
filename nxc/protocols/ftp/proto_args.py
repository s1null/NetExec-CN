from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    ftp_parser = parser.add_parser("ftp", help="使用FTP协议攻击目标", parents=parents, formatter_class=DisplayDefaultsNotNone)
    ftp_parser.add_argument("--port", type=int, default=21, help="FTP端口")

    cgroup = ftp_parser.add_argument_group("文件操作", "枚举和操作目标上文件的选项")
    cgroup.add_argument("--ls", metavar="DIRECTORY", nargs="?", const=".", help="列出目录中的文件")
    cgroup.add_argument("--get", metavar="FILE", help="下载文件")
    cgroup.add_argument("--put", metavar=("LOCAL_FILE", "REMOTE_FILE"), nargs=2, help="上传文件")
    return parser

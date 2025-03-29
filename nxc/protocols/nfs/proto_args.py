def proto_args(parser, parents):
    nfs_parser = parser.add_parser("nfs", help="使用NFS协议攻击目标", parents=parents)
    nfs_parser.add_argument("--port", type=int, default=111, help="NFS端口映射器端口（默认：%(default)s）")
    nfs_parser.add_argument("--nfs-timeout", type=int, default=5, help="NFS连接超时（默认：%(default)s秒）")

    dgroup = nfs_parser.add_argument_group("NFS映射/枚举", "映射/枚举NFS的选项")
    dgroup.add_argument("--share", help="指定共享，例如用于--ls, --get-file, --put-file")
    dgroup.add_argument("--shares", action="store_true", help="列出NFS共享")
    dgroup.add_argument("--enum-shares", nargs="?", type=int, const=3, help="认证并递归枚举暴露的共享（默认深度：%(const)s）")
    dgroup.add_argument("--ls", const="/", nargs="?", metavar="PATH", help="列出指定NFS共享中的文件。示例：--ls /")
    dgroup.add_argument("--get-file", nargs=2, metavar="FILE", help="下载远程NFS文件。示例：--get-file 远程文件 本地文件")
    dgroup.add_argument("--put-file", nargs=2, metavar="FILE", help="上传NFS文件到指定文件夹并设置chmod 777权限。示例：--put-file 本地文件 远程文件")

    return parser

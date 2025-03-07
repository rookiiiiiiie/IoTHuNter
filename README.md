# IoTHuNter
# 简介
一个自动化分析危险函数的IDA插件，它结合了逆向工程中的函数审计功能和人工智能（AI）分析，用于帮助分析二进制文件中的潜在安全问题和弱点，支持处理ARM与MIPS架构。

# 功能
- **架构特定的函数审计**
    - 支持 **ARM** 和 **MIPS** 两种架构的二进制文件分析。
    - 通过静态分析，检测代码中调用潜在危险函数（如 strcpy、system 等）的使用情况，并提取相关信息（如参数、调用地址、本地缓冲区大小等）。
    - 将审计结果以表格形式（使用 PrettyTable）输出，便于用户查看。
- **AI 辅助代码分析**
    - 集成了 **OpenAI API**（默认使用 deepseek-chat 模型），通过右键菜单或快捷键对伪代码（由 Hex-Rays 反编译器生成）进行智能分析。
    - 分析内容包括：
        - 函数的预期目的、参数作用、详细逻辑。
        - 潜在的安全隐患或漏洞。
        - 可能的利用方法，并建议用 Python 编写 PoC（概念验证）脚本。
    - AI 分析结果会作为函数注释添加到 IDA 中。
- **用户交互与界面增强**
    - 在 IDA 的伪代码窗口中添加右键菜单选项（IoTHuNter/Analyze Function）。
    - 支持中英文提示（通过 ZH_CN 变量控制）。
    - 在 IDA 的菜单栏（Edit 菜单）中添加插件入口。
- **插件管理**
    - 插件初始化时检查 Hex-Rays 反编译器的可用性，并注册相关动作。
    - 支持热键（Ctrl-Alt-T 启动插件，Ctrl-Alt-G 触发 AI 分析）。
    - 在插件终止时清理资源。

# 使用

![image](https://github.com/user-attachments/assets/d5b0b8d3-a716-4544-81a8-21c8be211768)


双击函数地址跳转相应位置

![image](https://github.com/user-attachments/assets/8296f737-ca92-43ec-a83f-fd751027b1bb)


![image](https://github.com/user-attachments/assets/d0667bee-28a2-48fc-b642-de8dd83d8fb8)


反汇编界面右键选择`IoTHuNter/Analyze Function`
![image](https://github.com/user-attachments/assets/6031e9c8-1430-46ad-b5b8-902f4c5ea44d)

等待回显

![image](https://github.com/user-attachments/assets/ef81106d-07f2-4163-8f02-e32c8ff97f3c)

![image](https://github.com/user-attachments/assets/71e2bbc0-7094-40c6-8df6-dd78eb2b9181)


# 可以扫描的函数

```
# 函数列表

dangerous_functions = [
    "strcpy", "strcat", "sprintf", "read", "getenv",
    "gets", "scanf", "vsprintf", "strnlen", "wcscpy"
]
attention_function = [
    "memcpy", "malloc", "strncpy", "sscanf", "strncat", "snprintf", "vprintf", "printf",
    "memset", "free", "strlen", "wcsncpy", "vfscanf"
]
command_execution_function = [
    "system", "execve", "popen", "unlink", "dosystem",
    "execl", "execvp", "remove", "rename", "fork"
]
one_arg_function = [
    "malloc", "getenv", "system", "unlink", "dosystem",
    "gets", "free", "strlen", "remove", "fork"
]
two_arg_function = [
    "strcpy", "strcat", "popen",
    "wcscpy", "rename", "fork"
] 
three_arg_function = [
    "strncpy", "strncat", "memcpy", "execve", "read",
    "memset", "wcsncpy", "strnlen"
]
format_function_offset_dict = {
    "sprintf": 1, "sscanf": 1, "snprintf": 2, "vprintf": 0, "printf": 0,
    "vsprintf": 1, "scanf": 0, "vfscanf": 1
}
```

# 安装

![image](https://github.com/user-attachments/assets/6766e1a3-9aa4-45c2-8002-20a5a5a15bb5)

IoTHuNter.py -> plugins
![image](https://github.com/user-attachments/assets/01800486-bb57-49f6-ae41-31c71f65096f)

此版本基于IDA_pro_7.7版本，IDA9.0请修改注释，以及
```
#import ida_ida     #ida9
```
需要根据自己IDA版本进行修改，以及外部依赖的安装
# 用途

- **逆向工程**：帮助分析 IoT 固件的潜在漏洞。
- **攻击原理**：通过 AI 生成的详细解释和 PoC，辅助理解漏洞原理。
- **安全审计**：自动化检测危险函数调用并提供深入分析。

# 联系我
如果使用插件时遇到问题或有任何疑问，请留言或邮件联系我。

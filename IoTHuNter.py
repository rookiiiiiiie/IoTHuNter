from idaapi import *
import idaapi
import idc
from prettytable import PrettyTable
import functools
import ida_hexrays
import ida_kernwin
import openai
import re
import threading
import json
import sys, os
#import ida_ida     #ida9

# 检查 IDA SDK 版本兼容性
if idaapi.IDA_SDK_VERSION > 700:
    import ida_search
    from idc import print_operand
    from ida_bytes import get_strlit_contents
else:
    from idc import GetOpnd as print_operand, GetString
    def get_strlit_contents(*args):
        return GetString(args[0])

# 设置 OpenAI 配置
client = openai.OpenAI(api_key="", base_url="") #自行添加api_key，base_url例如：https://api.deepseek.com
JSON_REGEX = re.compile(r"\{[^}]*?\}")
ZH_CN = True  # 是否使用中文提示

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

def printFunc(func_name):
    string1 = "========================================"
    string2 = "========== Auditing " + func_name + " "
    strlen = len(string1) - len(string2)
    return string1 + "\n" + string2 + '=' * strlen + "\n" + string1

def getFuncAddr(func_name):
    func_addr = idc.get_name_ea_simple(func_name)
    if func_addr != BADADDR:
        print(printFunc(func_name))
        return func_addr
    return False

# ARM 审计类
class CArmAudit:
    def getArgAddr(self, start_addr, regNum):
        armcondition = []
        scan_deep = 50
        count = 0
        reg = "R" + str(regNum)
        before_addr = get_first_cref_to(start_addr)
        while before_addr != BADADDR:
            if reg == idc.print_operand(before_addr, 0):
                Mnemonics = print_insn_mnem(before_addr)
                if Mnemonics[0:2] in armcondition or Mnemonics[0:1] == "B":
                    pass
                else:
                    return before_addr
            count = count + 1
            if count > scan_deep:
                break
            before_addr = get_first_cref_to(before_addr)
        return BADADDR

    def getArg(self, start_addr, regNum):
        arm = ['LDR', 'CMP', 'STR', 'MOV']
        arg_addr = self.getArgAddr(start_addr, regNum)
        if arg_addr != BADADDR:
            Mnemonics = idc.print_insn_mnem(arg_addr)
            if Mnemonics[0:3] == "ADD":
                pc_rx_str = idc.print_operand(arg_addr, 1) + "+" + idc.print_operand(arg_addr, 2)
                if pc_rx_str[0:4] == "PC+R":
                    mid_addr = self.getArgAddr(arg_addr, int(pc_rx_str[-1]))
                    arg = idc.print_operand(arg_addr, 1) + "+" + idc.print_operand(mid_addr, 1)
                else:
                    arg = pc_rx_str
            elif Mnemonics[0:3] == "SUB":
                arg = idc.print_operand(arg_addr, 1) + "-" + idc.print_operand(arg_addr, 2)
            elif Mnemonics[0:3] in arm:
                arg = idc.print_operand(arg_addr, 1)
            else:
                arg = idc.generate_disasm_line(arg_addr, 1).split(" ")[0]
            set_cmt(arg_addr, "addr: 0x%x " % start_addr + "-------> arg" + str((int(regNum) + 1)) + " : " + arg, 0)
            return arg
        else:
            return "get fail"

    def auditAddr(self, call_addr, func_name, arg_num):
        addr = "0x%x" % call_addr
        ret_list = [func_name, addr]
        local_buf_size = idc.get_func_attr(call_addr, idc.FUNCATTR_FRSIZE)
        if local_buf_size == BADADDR:
            local_buf_size = "get fail"
        else:
            local_buf_size = "0x%x" % local_buf_size
        for num in range(0, arg_num):
            ret_list.append(self.getArg(call_addr, num))
        ret_list.append(local_buf_size)
        return ret_list

    def getFormatString(self, addr):
        op_num = 1
        if idc.get_operand_type(addr, op_num) != 2:
            return "get fail"
        op_string = idc.print_operand(addr, op_num).split(" ")[0].replace("=(", "")
        if '+0x' in op_string:
            offset = op_string.split("+")[1]
            op_string = op_string.split("+")[0]
            string_addr = idc.get_name_ea_simple(op_string)
            string_addr = string_addr + int(offset, 16)
        else:
            string_addr = idc.get_name_ea_simple(op_string)
        if string_addr == BADADDR:
            return "get fail"
        string = str(get_strlit_contents(string_addr, -1, STRTYPE_TERMCHR))
        return [string_addr, string, op_string]

    def auditFormat(self, call_addr, func_name, arg_num):
        addr = "0x%x" % call_addr
        ret_list = [func_name, addr]
        local_buf_size = idc.get_func_attr(call_addr, idc.FUNCATTR_FRSIZE)
        if local_buf_size == BADADDR:
            local_buf_size = "get fail"
        else:
            local_buf_size = "0x%x" % local_buf_size
        for num in range(0, arg_num):
            ret_list.append(self.getArg(call_addr, num))
        mid_arg_addr = self.getArgAddr(call_addr, format_function_offset_dict[func_name])
        Rx_arg = self.getArg(call_addr, format_function_offset_dict[func_name])
        if Rx_arg in ['R9', 'R11', 'R4', 'R6', 'R10']:
            if len(Rx_arg) == 2:
                true_arg_addr = self.getArgAddr(mid_arg_addr, int(Rx_arg[-1]))
                true_arg_addr = self.getArgAddr(true_arg_addr, int(Rx_arg[-1]))
            else:
                true_arg_addr = self.getArgAddr(mid_arg_addr, int(Rx_arg[1:]))
                true_arg_addr = self.getArgAddr(true_arg_addr, int(Rx_arg[1:]))
        else:
            true_arg_addr = self.getArgAddr(mid_arg_addr, format_function_offset_dict[func_name])
        string_and_addr = self.getFormatString(true_arg_addr)
        if Rx_arg in ['R9', 'R11', 'R4', 'R6', 'R10']:
            format_arg = string_and_addr[2]
            ret_list.pop(-1)
            ret_list.append(format_arg)
        format_and_value = []
        if string_and_addr == "get fail":
            ret_list.append("get fail")
        else:
            string_addr = "0x%x" % string_and_addr[0]
            format_and_value.append(string_addr)
            string = string_and_addr[1]
            fmt_num = string.count("%")
            format_and_value.append(fmt_num)
            if fmt_num + arg_num >= 4:
                fmt_num = 4
            else:
                fmt_num = fmt_num + arg_num
            for num in range(arg_num, fmt_num):
                format_and_value.append(self.getArg(call_addr, num))
            ret_list.append(format_and_value)
        ret_list.append(local_buf_size)
        return ret_list

    def audit(self, func_name):
        func_addr = getFuncAddr(func_name)
        if func_addr == False:
            return False
        if func_name in one_arg_function:
            arg_num = 1
        elif func_name in two_arg_function:
            arg_num = 2
        elif func_name in three_arg_function:
            arg_num = 3
        elif func_name in format_function_offset_dict:
            arg_num = format_function_offset_dict[func_name] + 1
        else:
            print("The %s function didn't write in the describe arg num of function array, please add it to, such as add to `two_arg_function` array" % func_name)
            return
        table_head = ["func_name", "addr"]
        for num in range(0, arg_num):
            table_head.append("arg" + str(num + 1))
        if func_name in format_function_offset_dict:
            table_head.append("format&value[string_addr, num of '%', fmt_arg...]")
        table_head.append("local_buf_size")
        table = PrettyTable(table_head)
        call_addr = get_first_cref_to(func_addr)
        while call_addr != BADADDR:
            idc.set_color(call_addr, idc.CIC_ITEM, 0xffff00)
            Mnemonics = print_insn_mnem(call_addr)
            if Mnemonics[0:1] == "B":
                if func_name in format_function_offset_dict:
                    info = self.auditFormat(call_addr, func_name, arg_num)
                else:
                    info = self.auditAddr(call_addr, func_name, arg_num)
                table.add_row(info)
            call_addr = get_next_cref_to(func_addr, call_addr)
        print(table)

    def ArmAudit(self):
        print("Auditing dangerous functions ......")
        for func_name in dangerous_functions:
            self.audit(func_name)
        print("Auditing attention function ......")
        for func_name in attention_function:
            self.audit(func_name)
        print("Auditing command execution function ......")
        for func_name in command_execution_function:
            self.audit(func_name)
        print("Finished! Enjoy the result ~")

# MIPS 审计类
class CMipsAudit:
    def getFormatString(self, addr):
        op_num = 1
        if idc.get_operand_type(addr, op_num) != 5:
            op_num = op_num + 1
        if idc.get_operand_type(addr, op_num) != 5:
            return "get fail"
        op_string = print_operand(addr, op_num).split(" ")[0].split("+")[0].split("-")[0].replace("(", "")
        string_addr = idc.get_name_ea_simple(op_string)
        if string_addr == BADADDR:
            return "get fail"
        string = str(get_strlit_contents(string_addr, -1, STRTYPE_TERMCHR))
        return [string_addr, string, op_string]

    def get_Tpye_ArgAddr(self, start_addr, regNum, argType):
        mipscondition = ["bn", "be", "bg", "bl"]
        scan_deep = 100
        count = 0
        reg = argType + str(regNum)
        before_addr = get_first_cref_to(start_addr)
        while before_addr != BADADDR:
            if reg == print_operand(before_addr, 0):
                Mnemonics = print_insn_mnem(before_addr)
                if Mnemonics[0:2] in mipscondition or Mnemonics[0:1] == "j":
                    pass
                else:
                    return before_addr
            count = count + 1
            if count > scan_deep:
                break
            before_addr = get_first_cref_to(before_addr)
        return BADADDR

    def getArg(self, start_addr, regNum):
        mipsmov = ["move", "lw", "li", "lb", "lui", "lhu", "lbu", "la"]
        arg_addr = self.get_Tpye_ArgAddr(start_addr, regNum, "$a")
        if arg_addr != BADADDR:
            Mnemonics = print_insn_mnem(arg_addr)
            if Mnemonics[0:3] == "add":
                if print_operand(arg_addr, 2) == "":
                    arg = print_operand(arg_addr, 0) + "+" + print_operand(arg_addr, 1)
                else:
                    arg = print_operand(arg_addr, 1) + "+" + print_operand(arg_addr, 2)
            elif Mnemonics[0:3] == "sub":
                if print_operand(arg_addr, 2) == "":
                    arg = print_operand(arg_addr, 0) + "-" + print_operand(arg_addr, 1)
                else:
                    arg = print_operand(arg_addr, 1) + "-" + print_operand(arg_addr, 2)
            elif Mnemonics in mipsmov:
                arg = print_operand(arg_addr, 1)
            else:
                arg = idc.generate_disasm_line(arg_addr, 1).split("#")[0]
            set_cmt(arg_addr, "addr: 0x%x " % start_addr + "-------> arg" + str((int(regNum) + 1)) + " : " + arg, 0)
            return arg
        else:
            return "get fail"

    def auditAddr(self, call_addr, func_name, arg_num):
        addr = "0x%x" % call_addr
        ret_list = [func_name, addr]
        local_buf_size = idc.get_func_attr(call_addr, idc.FUNCATTR_FRSIZE)
        if local_buf_size == BADADDR:
            local_buf_size = "get fail"
        else:
            local_buf_size = "0x%x" % local_buf_size
        for num in range(0, arg_num):
            ret_list.append(self.getArg(call_addr, num))
        ret_list.append(local_buf_size)
        return ret_list

    def auditFormat(self, call_addr, func_name, arg_num):
        addr = "0x%x" % call_addr
        ret_list = [func_name, addr]
        local_buf_size = idc.get_func_attr(call_addr, idc.FUNCATTR_FRSIZE)
        if local_buf_size == BADADDR:
            local_buf_size = "get fail"
        else:
            local_buf_size = "0x%x" % local_buf_size
        for num in range(0, arg_num):
            ret_list.append(self.getArg(call_addr, num))
        mid_arg_addr = self.get_Tpye_ArgAddr(call_addr, format_function_offset_dict[func_name], "$a")
        xx_arg = self.getArg(call_addr, format_function_offset_dict[func_name])
        if xx_arg in ['$v0', '$v1', '$v2']:
            true_arg_addr = self.get_Tpye_ArgAddr(mid_arg_addr, int(xx_arg[-1]), "$v")
        elif xx_arg in ['$s1', '$s0']:
            true_arg_addr = self.get_Tpye_ArgAddr(mid_arg_addr, int(xx_arg[-1]), "$s")
        elif xx_arg in ["$a0", "$a1", "$a2"] and int(xx_arg[-1]) != format_function_offset_dict[func_name]:
            true_arg_addr = self.get_Tpye_ArgAddr(mid_arg_addr, int(xx_arg[-1]), "$a")
        else:
            true_arg_addr = mid_arg_addr
        string_and_addr = self.getFormatString(true_arg_addr)
        format_arg = string_and_addr[2]
        ret_list.pop(-1)
        ret_list.append(format_arg)
        format_and_value = []
        if string_and_addr == "get fail":
            ret_list.append("get fail")
        else:
            string_addr = "0x%x" % string_and_addr[0]
            format_and_value.append(string_addr)
            string = string_and_addr[1]
            fmt_num = string.count("%")
            format_and_value.append(fmt_num)
            if fmt_num + arg_num >= 4:
                fmt_num = 4
            else:
                fmt_num = fmt_num + arg_num
            for num in range(arg_num, fmt_num):
                format_and_value.append(self.getArg(call_addr, num))
            ret_list.append(format_and_value)
        ret_list.append(local_buf_size)
        return ret_list

    def audit(self, func_name):
        func_addr = getFuncAddr(func_name)
        if func_addr == False:
            return False
        if func_name in one_arg_function:
            arg_num = 1
        elif func_name in two_arg_function:
            arg_num = 2
        elif func_name in three_arg_function:
            arg_num = 3
        elif func_name in format_function_offset_dict:
            arg_num = format_function_offset_dict[func_name] + 1
        else:
            print("The %s function didn't write in the describe arg num of function array, please add it to, such as add to `two_arg_function` array" % func_name)
            return
        table_head = ["func_name", "addr"]
        for num in range(0, arg_num):
            table_head.append("arg" + str(num + 1))
        if func_name in format_function_offset_dict:
            table_head.append("format&value[string_addr, num of '%', fmt_arg...]")
        table_head.append("local_buf_size")
        table = PrettyTable(table_head)
        call_addr = get_first_cref_to(func_addr)
        while call_addr != BADADDR:
            idc.set_color(call_addr, idc.CIC_ITEM, 0xffff00)
            Mnemonics = print_insn_mnem(call_addr)
            if Mnemonics[0:1] == "j" or Mnemonics[0:1] == "b":
                if func_name in format_function_offset_dict:
                    info = self.auditFormat(call_addr, func_name, arg_num)
                else:
                    info = self.auditAddr(call_addr, func_name, arg_num)
                table.add_row(info)
            call_addr = get_next_cref_to(func_addr, call_addr)
        print(table)

    def MipsAudit(self):
        print("Auditing dangerous functions ......")
        for func_name in dangerous_functions:
            self.audit(func_name)
        print("Auditing attention function ......")
        for func_name in attention_function:
            self.audit(func_name)
        print("Auditing command execution function ......")
        for func_name in command_execution_function:
            self.audit(func_name)
        print("Finished! Enjoy the result ~")

# WPeChatGPT 的 ExplainHandler
class ExplainHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = idaapi.get_screen_ea()
        funcComment = idc.get_func_cmt(ea, 0) or idc.get_func_cmt(ea, 1) or ""
        if "---GPT_START---" in funcComment:
            if ZH_CN:
                print("当前函数已完成 AI 分析，请查看或清除注释后重试。")
            else:
                print("The current function has already been analyzed by AI. Please check or remove the comment to re-analyze.")
            return 0
        if not ida_hexrays.init_hexrays_plugin():
            print("Hex-Rays decompiler is not available. AI analysis requires Hex-Rays.")
            return 0
        try:
            decompiler_output = ida_hexrays.decompile(ea)
        except:
            print(f"Failed to decompile function at {hex(ea)}. Ensure Hex-Rays is properly installed.")
            return 0
        v = ida_hexrays.get_widget_vdui(ctx.widget) if ctx.widget else None
        if ZH_CN:
            query_text = (
                "你是网络安全专业教师，精通各种语言及不同架构的汇编和漏洞。"
                "下面是一个 C 语言伪代码函数，请分析其预期目的、参数作用、详细功能，以及函数逻辑，让学生们更清晰的理解。继续查找下面 C 语言伪代码函数的存在的安全隐患或者漏洞并提出可能的利用方法最好用python写出poc验证脚本，让学生们更好的理解漏洞原理。（回答前加'---GPT_START---'，结尾加'---GPT_END---'）\n"
                f"{decompiler_output}"
            )
        else:
            query_text = (
                "You are a cybersecurity expert and teacher, proficient in various programming languages, assembly across different architectures, and vulnerabilities. "
                "Below is a C language pseudocode function. Please analyze its intended purpose, the role of its parameters, its detailed functionality, and its logic to help students understand it clearly. "
                "Additionally, identify any security risks or vulnerabilities in the C pseudocode function below and suggest possible exploitation methods, ideally providing a Python PoC (Proof of Concept) script to verify the vulnerabilities, enabling students to better understand the principles behind them. (Prepend your response with '---GPT_START---' and append '---GPT_END---')\n"
                f"{decompiler_output}"
            )
        query_model_async(
            query_text,
            functools.partial(comment_callback, address=ea, view=v, cmtFlag=0, printFlag=0),
            0
        )
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# WPeChatGPT 的查询和回调函数
def query_model(query, cb, max_tokens=1024):
    try:
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": "You are a helpful assistant"},
                {"role": "user", "content": query}
            ],
            temperature=0.7,
            stream=False
        )
        ida_kernwin.execute_sync(functools.partial(cb, response=response.choices[0].message.content), ida_kernwin.MFF_WRITE)
    except Exception as e:
        print(f"查询过程中遇到异常：{str(e)}")

def query_model_async(query, cb, time):
    if time == 0:
        print("正在发送 AI 请求，请稍候...")
    else:
        print("正在重新发送 AI 请求...")
    t = threading.Thread(target=query_model, args=[query, cb])
    t.daemon = True
    t.start()

def comment_callback(address, view, response, cmtFlag, printFlag):
    if cmtFlag == 0:
        idc.set_func_cmt(address, response, 0)
    if view:
        view.refresh_view(False)
    print("AI 查询完成！")
    if printFlag == 0:
        if ZH_CN:
            print(f"AI 分析完成，已为函数 {idc.get_func_name(address)} 添加注释。")
        else:
            print(f"AI analysis finished, function {idc.get_func_name(address)} commented.")

# UI 钩子：添加右键菜单到伪代码窗口
class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        widget_type = idaapi.get_widget_type(form)
        # 限制到 Pseudocode Window (type: 48)
        if widget_type == 48:
            idaapi.attach_action_to_popup(form, popup, "IoTHuNter:Explain_Function", "IoTHuNter/Analyze Function")

# 插件主类
m_initialized = False
context_hooks = None

class IoTHuNter_Plugin_t(idaapi.plugin_t):
    comment = "AI-assisted audit plugin for IDA Pro"
    help = "Combines function auditing with AI analysis for IoT binaries"
    wanted_name = "IoTHuNter"
    wanted_hotkey = "Ctrl-Alt-T"
    flags = idaapi.PLUGIN_KEEP

    explain_action_name = "IoTHuNter:Explain_Function"
    explain_menu_path = "Edit/IoTHuNter/Analyze Function"

    def init(self):
        global m_initialized, context_hooks
        if m_initialized is False:
            m_initialized = True
            print("=" * 80)
            start = '''
   _   _       _   _       _   _        
  / \ / \     / \ / \     / \ / \     
 /   V   \   /   V   \   /   V   \   
 \       /   \       /   \       /   
  \     /     \     /     \     /     
   \   /       \   /       \   /         
    \ /         \ /         \ /            
     V           V           V             
  I   o   T   H   u   N   t   e   r     
  re-edit by rookiiiiiiie  2025.3.6
            '''
            print(start)
            print("=" * 80)

            # 检查 Hex-Rays
            if not ida_hexrays.init_hexrays_plugin():
                print("Warning: Hex-Rays decompiler not available. AI analysis will not work.")
            
            # 注册 ExplainHandler 动作
            explain_action = idaapi.action_desc_t(
                self.explain_action_name,
                'IoTHuNter/Analyze Function',
                ExplainHandler(),
                "Ctrl+Alt+G",
                'Analyze the current function using AI',
                199
            )
            if idaapi.register_action(explain_action):
                print("AI analysis action registered successfully.")
            else:
                print("Failed to register AI analysis action.")
            idaapi.attach_action_to_menu(self.explain_menu_path, self.explain_action_name, idaapi.SETMENU_APP)
            print("AI analysis action attached to Edit menu.")

            # 安装右键菜单钩子
            context_hooks = ContextMenuHooks()
            if context_hooks.hook():
                print("Context menu hooks installed successfully.")
            else:
                print("Failed to install context menu hooks.")
        return idaapi.PLUGIN_KEEP

    def term(self):
        global context_hooks
        if context_hooks:
            context_hooks.unhook()
            context_hooks = None
        idaapi.detach_action_from_menu(self.explain_menu_path, self.explain_action_name)
        print("Plugin terminated.")

    def run(self, arg):
        info = idaapi.get_inf_structure()
        print(info.procname)
        if 'mips' in info.procname:
            m_mips = CMipsAudit()
            m_mips.MipsAudit()
        elif 'ARM' in info.procname:
            m_arm = CArmAudit()
            m_arm.ArmAudit()
        else:
            print('IoTHuNter is not supported on the current arch')

    # def run(self, arg):
    #     info = ida_ida.inf_get_procname().lower()
    #     print(info)
    #     if 'mips' in info:
    #         m_mips = CMipsAudit()
    #         m_mips.MipsAudit()
    #     elif 'arm' in info:
    #         m_arm = CArmAudit()
    #         m_arm.ArmAudit()
    #     else:
    #         print('IoTHuNter is not supported on the current arch')   ida9
 
def PLUGIN_ENTRY():
    if not client.api_key or client.api_key == "ENTER_OPEN_API_KEY_HERE":
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            print("未找到 API_KEY，请设置 OPENAI_API_KEY 环境变量或在脚本中填写！")
            raise ValueError("No valid OpenAI API key found")
        client.api_key = api_key
    return IoTHuNter_Plugin_t()
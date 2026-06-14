"""
历史记录管理模块 (History Manager)
==================================
用于管理输入框的历史记录，支持撤销(Ctrl+Z)和重做(Ctrl+Y)操作

模块功能:
- 采用栈结构存储历史记录
- 支持最大记录数限制，防止内存溢出
- 提供撤销/重做功能
- 支持恢复状态标记，防止恢复操作触发新的历史记录保存

使用示例:
    history = HistoryManager(max_size=50)
    history.push("第一次输入")
    history.push("第二次输入")
    
    if history.can_undo():
        content = history.undo()  # 返回 "第一次输入"
    
    if history.can_redo():
        content = history.redo()  # 返回 "第二次输入"
"""


class HistoryManager:
    """
    历史记录管理器类
    
    用于管理输入框的历史记录，实现撤销(Ctrl+Z)和重做(Ctrl+Y)功能。
    采用列表模拟栈结构，通过索引指针实现前进后退。
    
    属性:
        history: 历史记录列表，存储所有历史内容
        current_index: 当前位置索引，指向当前显示的内容
        max_size: 最大历史记录数量限制
        is_restoring: 恢复状态标志，防止恢复操作触发新记录保存
    """
    
    def __init__(self, max_size=100):
        """
        初始化历史记录管理器
        
        参数:
            max_size (int): 最大历史记录数量，默认100条。
                           超过此数量时，最旧的记录会被删除。
        """
        self.history = []           # 历史记录列表，按时间顺序存储
        self.current_index = -1     # 当前位置索引，-1表示列表为空
        self.max_size = max_size    # 最大记录数，用于限制内存使用
        self.is_restoring = False   # 恢复状态标志，True时push操作不保存记录
        
    def push(self, content):
        """
        添加新的历史记录
        
        将新内容添加到历史记录列表。如果当前不在最新位置
        （即之前执行过撤销操作），会先删除当前位置之后的所有记录，
        然后再添加新记录。
        
        参数:
            content (str): 要保存的内容文本
            
        注意:
            如果is_restoring为True，此方法不会保存记录，
            这用于防止撤销/重做操作触发新的历史记录保存
        """
        # 如果正在恢复状态，不保存记录
        if self.is_restoring:
            return
            
        # 如果当前不在最新位置，删除当前位置之后的所有记录
        # 例如：历史为[A, B, C]，当前在B，添加D后变为[A, B, D]
        if self.current_index < len(self.history) - 1:
            self.history = self.history[:self.current_index + 1]
            
        # 添加新记录到列表末尾
        self.history.append(content)
        self.current_index = len(self.history) - 1
        
        # 如果超过最大数量，删除最旧的记录
        if len(self.history) > self.max_size:
            self.history.pop(0)  # 删除第一条记录
            self.current_index -= 1  # 索引相应减1
            
    def undo(self):
        """
        撤销操作，返回上一个历史记录
        
        将当前位置向前移动一位，返回该位置的历史内容。
        不会删除任何记录，只是移动索引指针。
        
        返回:
            str: 上一个历史记录内容，如果无法撤销（已在最早位置）则返回None
            
        示例:
            历史记录: [A, B, C]，当前索引: 2（指向C）
            执行undo后，当前索引: 1（指向B），返回B
        """
        if self.current_index > 0:
            self.current_index -= 1
            return self.history[self.current_index]
        return None
        
    def redo(self):
        """
        重做操作，返回下一个历史记录
        
        将当前位置向后移动一位，返回该位置的历史内容。
        用于撤销后恢复到较新的状态。
        
        返回:
            str: 下一个历史记录内容，如果无法重做（已在最新位置）则返回None
            
        示例:
            历史记录: [A, B, C]，当前索引: 1（指向B）
            执行redo后，当前索引: 2（指向C），返回C
        """
        if self.current_index < len(self.history) - 1:
            self.current_index += 1
            return self.history[self.current_index]
        return None
        
    def can_undo(self):
        """
        检查是否可以执行撤销操作
        
        返回:
            bool: 如果当前不在最早位置（索引>0）返回True，否则返回False
        """
        return self.current_index > 0
        
    def can_redo(self):
        """
        检查是否可以执行重做操作
        
        返回:
            bool: 如果当前不在最新位置（索引<列表长度-1）返回True，否则返回False
        """
        return self.current_index < len(self.history) - 1
        
    def clear(self):
        """
        清空所有历史记录
        
        重置历史记录列表和索引，恢复到初始状态。
        通常在清空输入框时调用。
        """
        self.history.clear()
        self.current_index = -1
        
    def set_restoring(self, state):
        """
        设置恢复状态
        
        在执行撤销/重做操作时，需要将此状态设为True，
        以防止恢复操作触发新的历史记录保存。
        操作完成后应设回False。
        
        参数:
            state (bool): True表示正在恢复状态，push操作不会保存记录
            
        使用示例:
            history.set_restoring(True)   # 开始恢复
            input_text.setPlainText(content)  # 这不会触发历史记录保存
            history.set_restoring(False)  # 结束恢复
        """
        self.is_restoring = state

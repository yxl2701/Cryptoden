"""
递归解密模块
==============
支持递归解密和解码，当解密结果匹配到关键词时输出递归解密内容

功能:
- 递归尝试所有解密算法
- 多线程并行解密加速
- 检测匹配关键词（如flag、ctf等）
- 记录完整解密路径
- 保存解密成功记录
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from datetime import datetime
from threading import Lock
from queue import PriorityQueue
from PyQt5.QtCore import QThread, pyqtSignal, QObject
from utils.recursive_config import load_recursive_config
from utils.recursive_features import (
    detect_result_features,
    feature_score,
    is_allowed_by_text_features,
    is_feature_match,
    is_repeatable_recursive_algo,
)


RECORDS_FILE = Path(__file__).parent.parent / "config" / "decrypt_records.json"


def get_optimal_workers():
    """获取最优工作线程数，使用空闲资源的50%"""
    cpu_count = os.cpu_count() or 4
    optimal = max(2, cpu_count // 2)
    return min(optimal, 8)


class DecryptRecord:
    """解密记录类"""
    
    def __init__(self, original_text: str, final_result: str, 
                 decrypt_path: List[Dict], matched_patterns: List[str]):
        self.original_text = original_text
        self.final_result = final_result
        self.decrypt_path = decrypt_path
        self.matched_patterns = matched_patterns
        self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        return {
            'original_text': self.original_text[:500],
            'final_result': self.final_result[:500],
            'decrypt_path': self.decrypt_path,
            'matched_patterns': self.matched_patterns,
            'timestamp': self.timestamp
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'DecryptRecord':
        record = cls(
            data.get('original_text', ''),
            data.get('final_result', ''),
            data.get('decrypt_path', []),
            data.get('matched_patterns', [])
        )
        record.timestamp = data.get('timestamp', '')
        return record


class RecordManager:
    """解密记录管理器"""
    
    _instance = None
    _lock = Lock()
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, max_records: int = 100):
        if hasattr(self, '_initialized'):
            return
        self._initialized = True
        self.max_records = max_records
        self.records: List[DecryptRecord] = []
        self._records_lock = Lock()
        self._load_records()
    
    def _load_records(self):
        if RECORDS_FILE.exists():
            try:
                with open(RECORDS_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.records = [DecryptRecord.from_dict(r) for r in data]
            except:
                self.records = []
    
    def _save_records(self):
        RECORDS_FILE.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(RECORDS_FILE, 'w', encoding='utf-8') as f:
                json.dump([r.to_dict() for r in self.records], f, ensure_ascii=False, indent=2)
        except:
            pass
    
    def add_record(self, record: DecryptRecord):
        with self._records_lock:
            self.records.insert(0, record)
            if len(self.records) > self.max_records:
                self.records = self.records[:self.max_records]
            self._save_records()
    
    def get_records(self) -> List[DecryptRecord]:
        with self._records_lock:
            return self.records.copy()
    
    def clear_records(self):
        with self._records_lock:
            self.records = []
            self._save_records()


class RecursiveDecryptThread(QThread):
    """递归解密线程 - 使用QThread确保信号正确处理"""
    
    progress_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(dict)
    match_found_signal = pyqtSignal(dict)
    
    DEFAULT_PATTERNS = ['flag', 'ctf', 'key', 'password', 'secret', 'admin', 'root']
    
    def __init__(self, modules: Dict, text: str, patterns: List[str], 
                 case_sensitive: bool, max_depth: int, max_workers: int,
                 max_tasks: int, brute_force_small_keyspaces: bool):
        super().__init__()
        self.modules = modules
        self.text = text
        self.patterns = patterns if patterns else self.DEFAULT_PATTERNS
        self.case_sensitive = case_sensitive
        self.max_depth = max_depth
        self.max_workers = max_workers
        self.max_tasks = max_tasks
        self.brute_force_small_keyspaces = brute_force_small_keyspaces
        self._stop_flag = False
        
        self._visited_lock = Lock()
        self._visited_texts: Set[int] = set()
        self._results_lock = Lock()
        self._matched_results: List[Dict] = []
        self._all_results: List[Dict] = []
        self._attempt_count = 0
        self._candidate_count = 0
        self._queue_counter = 0
    
    def stop(self):
        self._stop_flag = True
    
    def run(self):
        """线程主入口"""
        try:
            self._do_decrypt()
        except Exception as e:
            self.progress_signal.emit(f"解密出错: {str(e)}")
            self.finished_signal.emit({
                'success': False,
                'matched_results': [],
                'all_results': [],
                'error': str(e)
            })
    
    def _do_decrypt(self):
        """执行递归解密。GUI 复用 CLI 递归核心，避免两套搜索策略不一致。"""
        try:
            from de_recursion import recursive_decrypt

            self.progress_signal.emit(f"开始递归解密 (深度:{self.max_depth})")
            cli_result = recursive_decrypt(
                self.text,
                base_path=Path(__file__).parent.parent,
                max_depth=self.max_depth,
                patterns=self.patterns,
                case_sensitive=self.case_sensitive,
                brute_force_small_keyspaces=self.brute_force_small_keyspaces,
            )

            matched_items = []
            best = cli_result.get('best')
            if best:
                matched_items.append(best)
            for item in cli_result.get('matched', []):
                if best and item.get('text') == best.get('text'):
                    continue
                matched_items.append(item)

            matched_results = []
            for item in matched_items:
                matched_results.append({
                    'text': item.get('text', ''),
                    'matched_patterns': item.get('matched_patterns', []),
                    'depth': item.get('depth', 0),
                    'path': item.get('chain', []),
                    'features': item.get('features') or detect_result_features(item.get('text', '')),
                })

            all_results = []
            for item in cli_result.get('all_chains', []):
                chain = item.get('chain', [])
                last_step = chain[-1] if chain else {}
                text = item.get('text', '')
                all_results.append({
                    'algorithm': last_step.get('algorithm', item.get('chain_summary', '')),
                    'result': text,
                    'depth': item.get('depth', 0),
                    'is_brute': bool(last_step.get('is_brute')),
                    'params': last_step.get('params', ''),
                    'features': detect_result_features(text),
                })

            result = {
                'success': bool(matched_results),
                'matched_results': matched_results,
                'all_results': all_results,
                'stats': {
                    'processed_tasks': cli_result.get('max_depth_reached', 0),
                    'attempts': cli_result.get('total_attempts', 0),
                    'candidates': len(all_results),
                    'queued_tasks': 0,
                    'matches': len(matched_results),
                    'max_tasks': cli_result.get('settings', {}).get('max_total_attempts', self.max_tasks),
                    'finish_reason': 'CLI递归核心完成',
                }
            }

            self.progress_signal.emit(
                f"递归解密结束: 尝试 {cli_result.get('total_attempts', 0)} 次 | "
                f"命中 {len(matched_results)} 个"
            )

            if result['matched_results']:
                best = result['matched_results'][0]
                record = DecryptRecord(
                    self.text, best['text'], best['path'], best['matched_patterns']
                )
                RecordManager().add_record(record)
                result['saved_record'] = True

            self.finished_signal.emit(result)
            return
        except Exception as e:
            self.progress_signal.emit(f"CLI递归核心失败，回退GUI递归: {str(e)}")

        """执行递归解密（兼容回退路径）"""
        self._visited_texts = set()
        self._matched_results = []
        self._all_results = []
        self._attempt_count = 0
        self._candidate_count = 0
        self._queue_counter = 0
        
        self.progress_signal.emit(f"开始递归解密 (深度:{self.max_depth}, 线程:{self.max_workers})")
        
        task_queue = PriorityQueue()
        self._put_task(task_queue, {'text': self.text, 'depth': 0, 'path': []})
        
        processed = 0
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        finish_reason = "队列已处理完成"

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            while not self._stop_flag and not task_queue.empty() and processed < self.max_tasks:
                try:
                    _, _, task = task_queue.get(timeout=0.5)
                except:
                    continue
                
                if self._stop_flag:
                    break
                
                current_text = task['text']
                current_depth = task['depth']
                current_path = task['path']
                
                if current_depth > self.max_depth:
                    continue
                
                text_hash = hash(current_text[:200])
                with self._visited_lock:
                    if text_hash in self._visited_texts:
                        continue
                    self._visited_texts.add(text_hash)
                
                matched = self._check_patterns(current_text)
                if matched:
                    self._add_match({
                        'text': current_text,
                        'matched_patterns': matched,
                        'depth': current_depth,
                        'path': current_path.copy(),
                        'features': detect_result_features(current_text)
                    })
                
                futures = []
                for algo_name, module in list(self.modules.items()):
                    if not is_allowed_by_text_features(current_text, algo_name):
                        continue
                    if not is_repeatable_recursive_algo(algo_name):
                        if any(step.get('algorithm') == algo_name for step in current_path):
                            continue
                    if self._stop_flag:
                        break
                    future = executor.submit(
                        self._try_decrypt_algo,
                        current_text, algo_name, module,
                        current_depth, current_path, task_queue
                    )
                    futures.append(future)
                
                for future in as_completed(futures, timeout=30):
                    if self._stop_flag:
                        break
                    try:
                        future.result()
                    except:
                        pass
                
                processed += 1

                if processed % 5 == 0 or processed == 1:
                    self.progress_signal.emit(self._format_progress(processed, task_queue.qsize()))

        if self._stop_flag:
            finish_reason = "用户停止"
        elif processed >= self.max_tasks and not task_queue.empty():
            finish_reason = f"达到最大任务数 {self.max_tasks}，仍有 {task_queue.qsize()} 个候选待处理"

        result = {
            'success': len(self._matched_results) > 0,
            'matched_results': self._matched_results.copy(),
            'all_results': self._all_results.copy(),
            'stats': {
                'processed_tasks': processed,
                'attempts': self._attempt_count,
                'candidates': self._candidate_count,
                'queued_tasks': task_queue.qsize(),
                'matches': len(self._matched_results),
                'max_tasks': self.max_tasks,
                'finish_reason': finish_reason,
            }
        }

        self.progress_signal.emit(
            f"递归解密结束: {finish_reason} | 任务 {processed}/{self.max_tasks} | "
            f"尝试 {self._attempt_count} 次 | 候选 {self._candidate_count} 个 | 命中 {len(self._matched_results)} 个"
        )
        
        if result['matched_results']:
            best = result['matched_results'][0]
            record = DecryptRecord(
                self.text, best['text'], best['path'], best['matched_patterns']
            )
            RecordManager().add_record(record)
            result['saved_record'] = True
        
        self.finished_signal.emit(result)

    def _format_progress(self, processed: int, queued: int) -> str:
        with self._results_lock:
            attempts = self._attempt_count
            candidates = self._candidate_count
            matches = len(self._matched_results)
        return (
            f"递归解密中: 任务 {processed}/{self.max_tasks}, 队列 {queued}, "
            f"尝试 {attempts} 次, 候选 {candidates} 个, 命中 {matches} 个"
        )
    
    def _check_patterns(self, text: str) -> List[str]:
        """检查匹配模式"""
        matched = []
        search_text = text if self.case_sensitive else text.lower()
        for pattern in self.patterns:
            search_pattern = pattern if self.case_sensitive else pattern.lower()
            if search_pattern in ('flag', 'ctf', 'key', 'password', 'secret'):
                flags = 0 if self.case_sensitive else re.IGNORECASE
                if re.search(rf'(?<![a-z0-9]){re.escape(pattern)}(?![a-z0-9])', text, flags):
                    matched.append(pattern)
            elif search_pattern in search_text:
                matched.append(pattern)
        return matched
    
    def _try_decrypt_algo(self, text: str, algo_name: str, module,
                           depth: int, path: List[Dict], task_queue: PriorityQueue):
        """尝试单个算法解密"""
        if self._stop_flag:
            return

        def iter_candidates():
            seen = set()
            if hasattr(module, 'decrypt'):
                result = module.decrypt(text)
                if result is not None:
                    result = str(result)
                    seen.add(result)
                    yield result, "", False

            if not self.brute_force_small_keyspaces:
                return

            decrypt_all = getattr(module, 'decrypt_all', None)
            if not callable(decrypt_all):
                return
            output = str(decrypt_all(text))
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                params = "爆破"
                candidate = line
                match = re.match(r'^(偏移量|shift)\s*([0-9]+)\s*[:：]\s*(.*)$', line, re.IGNORECASE)
                if match:
                    params = f"shift={match.group(2)}"
                    candidate = match.group(3)
                elif ':' in line or '：' in line:
                    sep = ':' if ':' in line else '：'
                    params, candidate = [part.strip() for part in line.split(sep, 1)]
                if candidate and candidate not in seen:
                    seen.add(candidate)
                    yield candidate, params, True

        try:
            for result_text, params, is_brute in iter_candidates():
                with self._results_lock:
                    self._attempt_count += 1
                if result_text and (result_text.startswith("错误") or result_text.startswith("解码错误")):
                    continue
                if not result_text or result_text == text:
                    continue
                features = detect_result_features(result_text)
                step = {
                    'algorithm': algo_name,
                    'depth': depth,
                    'is_brute': is_brute,
                    'params': params
                }
                new_path = path + [step]
                
                with self._results_lock:
                    self._candidate_count += 1
                    self._all_results.append({
                        'algorithm': algo_name,
                        'result': result_text,
                        'depth': depth,
                        'is_brute': is_brute,
                        'params': params,
                        'features': features
                    })
                
                matched = self._check_patterns(result_text)
                if matched:
                    self._add_match({
                        'text': result_text,
                        'matched_patterns': matched,
                        'depth': depth + 1,
                        'path': new_path,
                        'features': features
                    })
                
                if len(result_text) < 5000 and depth + 1 <= self.max_depth:
                    self._put_task(task_queue, {
                        'text': result_text,
                        'depth': depth + 1,
                        'path': new_path
                    })
        except Exception:
            pass

    def _put_task(self, task_queue: PriorityQueue, task: Dict):
        features = detect_result_features(task.get('text', ''))
        priority = task.get('depth', 0) * 20 - feature_score(features)
        with self._results_lock:
            self._queue_counter += 1
            counter = self._queue_counter
        task_queue.put((priority, counter, task))
    
    def _add_match(self, match: Dict):
        with self._results_lock:
            text_hash = hash(match['text'][:200])
            for existing in self._matched_results:
                if hash(existing['text'][:200]) == text_hash:
                    return
            self._matched_results.append(match)


class AsyncRecursiveDecryptor(QObject):
    """异步递归解密器"""
    
    finished = pyqtSignal(dict)
    progress = pyqtSignal(str)
    match_found = pyqtSignal(dict)
    
    def __init__(self, modules: Dict, max_depth: int = None, max_workers: int = None,
                 max_tasks: int = None, brute_force_small_keyspaces: bool = None):
        super().__init__()
        config = load_recursive_config()
        self.modules = modules
        self.max_depth = int(config["max_depth"] if max_depth is None else max_depth)
        self.max_workers = int(config["max_workers"] if max_workers is None else max_workers)
        self.max_tasks = int(config["max_tasks"] if max_tasks is None else max_tasks)
        self.brute_force_small_keyspaces = bool(
            config["brute_force_small_keyspaces"] if brute_force_small_keyspaces is None else brute_force_small_keyspaces
        )
        self._thread = None
        self.record_manager = RecordManager()
    
    def start(self, text: str, patterns: List[str] = None, case_sensitive: bool = False):
        if self._thread and self._thread.isRunning():
            self._thread.stop()
            self._thread.wait(1000)
        
        self._thread = RecursiveDecryptThread(
            self.modules, text, patterns, case_sensitive,
            self.max_depth, self.max_workers, self.max_tasks,
            self.brute_force_small_keyspaces
        )
        
        self._thread.progress_signal.connect(self.progress.emit)
        self._thread.finished_signal.connect(self._on_finished)
        self._thread.match_found_signal.connect(self.match_found.emit)
        
        self._thread.start()
    
    def _on_finished(self, result: dict):
        self.finished.emit(result)
    
    def stop(self):
        if self._thread and self._thread.isRunning():
            self._thread.stop()
            self._thread.wait(2000)
    
    def get_records(self) -> List[DecryptRecord]:
        return self.record_manager.get_records()
    
    def clear_records(self):
        self.record_manager.clear_records()

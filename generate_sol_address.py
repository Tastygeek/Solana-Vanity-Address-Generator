import base58
from solders.keypair import Keypair
from mnemonic import Mnemonic
import time
import multiprocessing as mp
from multiprocessing import Manager
import hashlib
import logging
from typing import Tuple, Optional, List, Dict
import os
import secrets
import psutil
from datetime import timedelta
import argparse
from bip_utils import (
    Bip39MnemonicValidator, 
    Bip39SeedGenerator,
    Bip32PathParser,
    Bip32Slip10Ed25519Blake2b
)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 全局计数器
show_process_details = False  # 是否显示每个进程的详细信息

# Solana的BIP44派生路径
DERIVATION_PATH = "m/44'/501'/0'/0'"

def derive_keypair_from_mnemonic(mnemonic: str) -> Tuple[Keypair, str]:
    """从助记词派生Solana密钥对，使用完整的BIP32-Ed25519推导
    
    使用bip_utils库实现完整的BIP32-Ed25519推导路径：
    1. 验证助记词
    2. 生成种子
    3. 使用BIP32-Ed25519算法派生密钥
    4. 转换为Solana密钥对
    """
    # 验证助记词
    Bip39MnemonicValidator().Validate(mnemonic)
    
    # 从助记词生成种子
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    
    # 创建BIP32-Ed25519对象
    bip32_mst_ctx = Bip32Slip10Ed25519Blake2b.FromSeed(seed_bytes)
    
    # 解析派生路径
    bip32_path = Bip32PathParser.Parse(DERIVATION_PATH)
    
    # 派生密钥（分步骤派生，而不是直接使用DerivePath）
    bip32_ctx = bip32_mst_ctx
    for path_elem in bip32_path:
        bip32_ctx = bip32_ctx.ChildKey(path_elem)
    
    # 获取私钥
    priv_key_bytes = bip32_ctx.PrivateKey().Raw().ToBytes()
    
    # 使用私钥生成Solana密钥对
    keypair = Keypair.from_seed(priv_key_bytes)
    
    return keypair, mnemonic

def test_keypair_derivation():
    """测试助记词到密钥对的推导是否正确"""
    # 生成助记词
    mnemo = Mnemonic("english")
    entropy = secrets.token_bytes(32)
    mnemonic = mnemo.to_mnemonic(entropy)
    
    # 从助记词派生keypair
    kp1, _ = derive_keypair_from_mnemonic(mnemonic)
    
    # 再次从相同助记词派生keypair
    kp2, _ = derive_keypair_from_mnemonic(mnemonic)
    
    # 检查两次派生的地址是否一致
    addr1 = str(kp1.pubkey())
    addr2 = str(kp2.pubkey())
    
    # 如果地址不一致，说明派生过程有问题
    if addr1 != addr2:
        logger.error(f"派生测试失败! 相同助记词生成的地址不一致:\n{addr1}\n{addr2}")
        return False
    else:
        logger.info(f"派生测试通过: 从相同助记词生成的地址一致")
        return True

def generate_keypair_with_mnemonic() -> Tuple[Keypair, str]:
    """生成标准BIP39助记词和对应的Solana密钥对"""
    # 生成熵
    entropy = secrets.token_bytes(32)  # 256位熵，生成24个单词的助记词
    
    # 从熵生成助记词
    mnemo = Mnemonic("english")
    mnemonic = mnemo.to_mnemonic(entropy)
    
    # 从助记词派生密钥对
    keypair, _ = derive_keypair_from_mnemonic(mnemonic)
    
    return keypair, mnemonic

def generate_keypairs_batch(batch_size: int) -> List[Tuple[Keypair, str]]:
    """预先批量生成密钥对，提高效率"""
    return [generate_keypair_with_mnemonic() for _ in range(batch_size)]

def process_task(prefix: str, batch_size: int, process_id: int, return_dict: dict) -> None:
    """处理任务的进程函数"""
    attempts = 0
    process_start_time = time.time()
    last_report_time = time.time()
    report_interval = 5  # 每5秒报告一次进度
    
    # 使用CPU亲和性绑定进程
    if hasattr(os, 'sched_setaffinity'):
        try:
            os.sched_setaffinity(0, {process_id % os.cpu_count()})
        except Exception as e:
            pass
    
    try:
        while True:
            # 批量生成密钥对
            pairs = generate_keypairs_batch(batch_size)
            
            # 检查每个地址
            for kp, mnemonic in pairs:
                attempts += 1
                addr = str(kp.pubkey())
                
                # 更新当前进程的尝试次数
                return_dict[f'attempts_{process_id}'] = attempts
                
                # 定期报告进度
                current_time = time.time()
                if show_process_details and current_time - last_report_time > report_interval:
                    elapsed = current_time - process_start_time
                    speed = attempts / elapsed if elapsed > 0 else 0
                    logger.info(f"进程 #{process_id} - 速度: {speed:.2f} 地址/秒, "
                                f"已检查: {attempts:,} 个地址")
                    last_report_time = current_time
                
                # 检查是否找到匹配
                if addr.startswith(prefix):
                    # 验证地址和助记词关联性
                    verification_kp, _ = derive_keypair_from_mnemonic(mnemonic)
                    verification_addr = str(verification_kp.pubkey())
                    
                    if verification_addr != addr:
                        logger.error(f"地址验证失败: {addr} != {verification_addr}")
                        continue
                    
                    return_dict['found'] = True
                    return_dict['address'] = addr
                    return_dict['mnemonic'] = mnemonic
                    return_dict['process_id'] = process_id
                    return_dict['process_attempts'] = attempts
                    return
            
            # 短暂休眠以避免CPU满载
            time.sleep(0.001)
            
    except KeyboardInterrupt:
        return
    except Exception as e:
        logger.error(f"进程 #{process_id} 发生错误: {str(e)}")
        return

def format_duration(seconds: float) -> str:
    """格式化持续时间为可读形式"""
    return str(timedelta(seconds=int(seconds)))

def format_number(num: int) -> str:
    """格式化数字，添加千位分隔符"""
    return f"{num:,}"

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='生成指定前缀的Solana地址')
    parser.add_argument('-p', '--prefix', type=str, default='Sol', 
                        help='要匹配的地址前缀 (默认: "Sol")')
    parser.add_argument('-b', '--batch-size', type=int, default=5000, 
                        help='每批生成的地址数量 (默认: 5000)')
    parser.add_argument('-c', '--cpu-cores', type=int, default=0, 
                        help='使用的CPU核心数量, 0表示自动 (默认: 0)')
    parser.add_argument('-d', '--details', action='store_true',
                        help='显示每个进程的详细信息 (默认: 不显示)')
    parser.add_argument('-i', '--interval', type=int, default=5,
                        help='统计信息更新间隔(秒) (默认: 5)')
    parser.add_argument('-t', '--test', action='store_true',
                        help='启动前测试助记词推导 (默认: 不测试)')
    return parser.parse_args()

def main():
    # 解析命令行参数
    args = parse_arguments()
    prefix = args.prefix
    batch_size = args.batch_size
    stats_interval = args.interval
    
    # 设置是否显示进程详细信息
    global show_process_details
    show_process_details = args.details
    
    logger.info(f"开始生成以 '{prefix}' 为前缀的Solana地址...")
    logger.info(f"使用标准BIP39助记词生成Solana密钥对")
    
    # 如果需要测试，则执行验证
    if args.test:
        if not test_keypair_derivation():
            logger.error("助记词推导测试失败，程序退出")
            return
        else:
            logger.info("助记词推导测试通过，继续执行")
    
    # 获取系统信息
    cpu_info = f"{psutil.cpu_count(logical=False)}核心/{psutil.cpu_count()}线程"
    memory_info = f"{psutil.virtual_memory().total / (1024**3):.1f}GB"
    logger.info(f"系统信息: CPU {cpu_info}, 内存 {memory_info}")
    
    # 确定进程数
    if args.cpu_cores > 0:
        num_processes = min(args.cpu_cores, mp.cpu_count())
    else:
        num_processes = max(mp.cpu_count() - 1, 1)  # 保留一个核心给系统
    
    logger.info(f"使用 {num_processes} 个进程并行搜索，每进程批处理大小: {batch_size}")
    
    # 创建进程安全的共享字典
    manager = Manager()
    return_dict = manager.dict()
    return_dict['found'] = False
    
    # 为每个进程初始化尝试次数
    for i in range(num_processes):
        return_dict[f'attempts_{i}'] = 0
    
    # 创建进程
    processes = []
    start_time = time.time()
    
    try:
        # 启动进程
        for i in range(num_processes):
            p = mp.Process(target=process_task, args=(prefix, batch_size, i, return_dict))
            processes.append(p)
            p.start()
        
        # 监控进程
        last_stats_time = time.time()
        
        while True:
            # 检查是否找到匹配
            if return_dict.get('found', False):
                break
            
            # 检查进程是否存活
            all_alive = False
            for p in processes:
                if p.is_alive():
                    all_alive = True
                    break
            
            if not all_alive:
                logger.error("所有进程已结束，但未找到匹配的地址")
                break
            
            # 定期输出统计信息
            current_time = time.time()
            if current_time - last_stats_time > stats_interval:
                elapsed = current_time - start_time
                total_attempts = sum(return_dict.get(f'attempts_{i}', 0) for i in range(num_processes))
                speed = total_attempts / elapsed if elapsed > 0 else 0
                
                logger.info(f"进度统计: 已检查 {format_number(total_attempts)} 个地址, "
                           f"用时 {format_duration(elapsed)}, "
                           f"速度 {speed:.2f} 地址/秒")
                last_stats_time = current_time
            
            time.sleep(0.1)
        
        # 处理结果
        if return_dict.get('found', False):
            end_time = time.time()
            duration = end_time - start_time
            total_attempts = sum(return_dict.get(f'attempts_{i}', 0) for i in range(num_processes))
            
            address = return_dict['address']
            mnemonic = return_dict['mnemonic']
            process_id = return_dict['process_id']
            
            # 额外验证
            verification_kp, _ = derive_keypair_from_mnemonic(mnemonic)
            verification_addr = str(verification_kp.pubkey())
            is_verified = verification_addr == address
            
            logger.info("\n" + "="*50)
            logger.info("🎉 找到匹配的地址！")
            logger.info("="*50)
            logger.info(f"匹配由进程 #{process_id} 找到")
            logger.info(f"总尝试次数: {format_number(total_attempts)}")
            logger.info(f"耗时: {format_duration(duration)} ({duration:.2f}秒)")
            logger.info(f"平均速度: {total_attempts / duration:.2f} 地址/秒")
            logger.info(f"地址验证: {'✅ 通过' if is_verified else '❌ 失败'}")
            logger.info("\n📝 钱包地址:")
            logger.info(f"{address}")
            logger.info("\n🔑 24位助记词 (兼容Phantom等钱包):")
            logger.info(f"{mnemonic}")
            logger.info("\n🔒 导入说明:")
            logger.info(f"此助记词使用标准BIP39助记词标准，可以导入Phantom等Solana钱包")
            logger.info(f"导入Phantom钱包时选择「恢复现有钱包」并输入助记词")
            logger.info("="*50)
            
            # 保存结果到文件
            with open(f"solana_wallet_{prefix}_{address[:8]}.txt", "w") as f:
                f.write(f"地址: {address}\n")
                f.write(f"助记词 (兼容Phantom等钱包): {mnemonic}\n")
                f.write(f"地址验证: {'通过' if is_verified else '失败'}\n")
                f.write(f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"尝试次数: {total_attempts}\n")
                f.write(f"耗时: {format_duration(duration)}\n")
            
            logger.info(f"✅ 结果已保存到文件: solana_wallet_{prefix}_{address[:8]}.txt\n")
            
    except KeyboardInterrupt:
        logger.info("\n程序已手动停止")
    except Exception as e:
        logger.error(f"发生错误: {str(e)}")
    finally:
        # 终止所有进程
        for p in processes:
            if p.is_alive():
                p.terminate()
        
        # 等待所有进程结束
        for p in processes:
            p.join()

if __name__ == "__main__":
    main() 
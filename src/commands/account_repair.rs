//! 账号索引修复工具
//! 
//! 用于修复 accounts.json 索引文件与 accounts/*.json 账号文件之间的不一致

use crate::modules::account::{get_data_dir, load_account_index, save_account_index};
use crate::models::{AccountIndex, AccountSummary};
use std::collections::HashSet;
use std::fs;

/// 修复账号索引与文件的不一致
pub fn repair_account_index() -> Result<(), String> {
    println!("=== Kiro Tools 账号修复工具 ===\n");
    
    let data_dir = get_data_dir()?;
    let accounts_dir = data_dir.join("accounts");
    
    println!("数据目录: {:?}", data_dir);
    println!("账号目录: {:?}\n", accounts_dir);

    if !accounts_dir.exists() {
        return Err(format!("账号目录不存在: {:?}", accounts_dir));
    }

    // 1. 读取当前索引
    let mut index = load_account_index().unwrap_or_else(|e| {
        println!("⚠️  无法加载索引文件: {}", e);
        println!("将创建新的索引文件\n");
        AccountIndex::new()
    });
    
    let index_ids: HashSet<String> = index.accounts.iter().map(|a| a.id.clone()).collect();

    // 2. 扫描账号文件
    let entries = fs::read_dir(&accounts_dir)
        .map_err(|e| format!("读取账号目录失败: {}", e))?;

    let mut file_ids = HashSet::new();
    let mut orphaned_files = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|e| format!("读取目录项失败: {}", e))?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        if let Some(id) = path.file_stem().and_then(|s| s.to_str()) {
            file_ids.insert(id.to_string());
            
            if !index_ids.contains(id) {
                orphaned_files.push((id.to_string(), path));
            }
        }
    }

    // 3. 找出索引中但文件不存在的账号
    let mut missing_files = Vec::new();
    for id in &index_ids {
        if !file_ids.contains(id) {
            missing_files.push(id.clone());
        }
    }

    // 4. 报告问题
    println!("=== 一致性检查结果 ===");
    println!("索引中的账号数: {}", index_ids.len());
    println!("文件系统中的账号数: {}", file_ids.len());
    
    if orphaned_files.is_empty() && missing_files.is_empty() {
        println!("\n✓ 索引与文件完全一致，无需修复");
        return Ok(());
    }

    if !orphaned_files.is_empty() {
        println!("\n⚠️  发现 {} 个孤立的账号文件（在文件系统中但不在索引中）:", orphaned_files.len());
        for (id, path) in &orphaned_files {
            println!("  - {} ({})", id, path.display());
        }
    }

    if !missing_files.is_empty() {
        println!("\n⚠️  发现 {} 个缺失的账号文件（在索引中但文件不存在）:", missing_files.len());
        for id in &missing_files {
            println!("  - {}", id);
        }
    }

    // 5. 修复
    println!("\n=== 开始修复 ===");

    // 5.1 将孤立文件添加到索引
    for (id, _path) in orphaned_files {
        match crate::modules::account::load_account(&id) {
            Ok(account) => {
                index.accounts.push(AccountSummary {
                    id: account.id.clone(),
                    email: account.email.clone(),
                    name: account.name.clone(),
                    disabled: account.disabled,
                    proxy_disabled: account.proxy_disabled,
                    created_at: account.created_at,
                    last_used: account.last_used,
                });
                println!("  ✓ 已将账号 {} 添加到索引", account.email);
            }
            Err(e) => {
                println!("  ✗ 无法加载账号 {}: {}", id, e);
            }
        }
    }

    // 5.2 从索引中移除缺失文件的账号
    for id in missing_files {
        index.accounts.retain(|a| a.id != id);
        println!("  ✓ 已从索引中移除账号 {}", id);
    }

    // 6. 保存修复后的索引
    save_account_index(&index)?;
    println!("\n✓ 索引已修复并保存");
    println!("✓ 当前索引包含 {} 个账号", index.accounts.len());

    Ok(())
}

#![allow(dead_code)]
use crate::models::Account;

pub trait SystemIntegration: Send + Sync {
    async fn on_account_switch(&self, account: &crate::models::Account) -> Result<(), String>;
    fn update_tray(&self);
    fn show_notification(&self, title: &str, body: &str);
}

pub struct HeadlessIntegration;

impl SystemIntegration for HeadlessIntegration {
    async fn on_account_switch(&self, account: &crate::models::Account) -> Result<(), String> {
        crate::modules::logger::log_info(&format!("[Headless] Account switched in memory: {}", account.email));
        Ok(())
    }

    fn update_tray(&self) {}

    fn show_notification(&self, title: &str, body: &str) {
        crate::modules::logger::log_info(&format!("[Log Notification] {}: {}", title, body));
    }
}

#[derive(Clone)]
pub enum SystemManager {
    Headless,
}

impl SystemManager {
    pub async fn on_account_switch(&self, account: &Account) -> Result<(), String> {
        match self {
            SystemManager::Headless => {
                let integration = HeadlessIntegration;
                integration.on_account_switch(account).await
            }
        }
    }

    pub fn update_tray(&self) {}

    pub fn show_notification(&self, title: &str, body: &str) {
        match self {
            SystemManager::Headless => {
                let integration = HeadlessIntegration;
                integration.show_notification(title, body);
            }
        }
    }
}

impl SystemIntegration for SystemManager {
    async fn on_account_switch(&self, account: &crate::models::Account) -> Result<(), String> {
        match self {
            SystemManager::Headless => {
                let integration = HeadlessIntegration;
                integration.on_account_switch(account).await
            }
        }
    }

    fn update_tray(&self) {}

    fn show_notification(&self, title: &str, body: &str) {
        match self {
            SystemManager::Headless => {
                let integration = HeadlessIntegration;
                integration.show_notification(title, body);
            }
        }
    }
}

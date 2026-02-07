//! VERITAS CLI Chat Example
//!
//! A simple command-line chat application demonstrating the VERITAS protocol API.
//!
//! ## Features
//!
//! - Create and manage identities
//! - Add and manage contacts by identity hash
//! - Send and receive encrypted messages (simulated)
//! - Verify contacts using safety numbers
//!
//! ## Usage
//!
//! Run with: `cargo run --release`
//!
//! Available commands:
//! - `/help` - Show available commands
//! - `/identity` - Show your identity hash
//! - `/contacts` - List all contacts
//! - `/add <hash> <name>` - Add a new contact
//! - `/remove <name>` - Remove a contact
//! - `/msg <name> <message>` - Send a message
//! - `/safety <name>` - Show safety number for contact
//! - `/quit` - Exit the application

use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use crossterm::ExecutableCommand;
use crossterm::style::{Color, ResetColor, SetForegroundColor};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::info;

use veritas_core::{ClientConfig, SafetyNumber, VeritasClient};
use veritas_identity::{IdentityHash, IdentityKeyPair, IdentityPublicKeys};

// =============================================================================
// Configuration
// =============================================================================

/// Application name for storage directory
const APP_NAME: &str = "veritas-chat";

/// Default password for demo purposes (in production, prompt user)
const DEFAULT_PASSWORD: &[u8] = b"demo_password_change_in_production";

// =============================================================================
// Contact Management
// =============================================================================

/// A contact in the address book.
///
/// Contacts store the mapping between human-readable names and
/// cryptographic identity hashes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact {
    /// Human-readable name for this contact
    pub name: String,

    /// The contact's identity hash (64 hex characters)
    pub identity_hash: String,

    /// Optional public keys for encryption (simulated)
    #[serde(skip)]
    pub public_keys: Option<IdentityPublicKeys>,

    /// When the contact was added
    pub added_at: i64,

    /// Whether the contact has been verified via safety number
    pub verified: bool,
}

impl Contact {
    /// Create a new contact from an identity hash string.
    pub fn new(name: String, identity_hash: String) -> Self {
        Self {
            name,
            identity_hash,
            public_keys: None,
            added_at: chrono::Utc::now().timestamp(),
            verified: false,
        }
    }

    /// Get the identity hash as an IdentityHash type.
    pub fn identity(&self) -> Result<IdentityHash> {
        IdentityHash::from_hex(&self.identity_hash)
            .map_err(|e| anyhow!("Invalid identity hash: {}", e))
    }
}

/// Contact storage manager.
///
/// Handles persistence of contacts to a JSON file.
#[derive(Debug)]
pub struct ContactStore {
    /// Path to the contacts file
    path: PathBuf,

    /// In-memory contact list (name -> Contact)
    contacts: HashMap<String, Contact>,
}

impl ContactStore {
    /// Load contacts from disk or create new store.
    pub fn load(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join("contacts.json");

        let contacts = if path.exists() {
            let content = std::fs::read_to_string(&path).context("Failed to read contacts file")?;
            serde_json::from_str(&content).context("Failed to parse contacts file")?
        } else {
            HashMap::new()
        };

        Ok(Self { path, contacts })
    }

    /// Save contacts to disk.
    pub fn save(&self) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create data directory")?;
        }

        let content =
            serde_json::to_string_pretty(&self.contacts).context("Failed to serialize contacts")?;
        std::fs::write(&self.path, content).context("Failed to write contacts file")?;

        Ok(())
    }

    /// Add a new contact.
    pub fn add(&mut self, contact: Contact) -> Result<()> {
        // Check for duplicate name
        if self.contacts.contains_key(&contact.name) {
            return Err(anyhow!("Contact '{}' already exists", contact.name));
        }

        // Check for duplicate hash
        for existing in self.contacts.values() {
            if existing.identity_hash == contact.identity_hash {
                return Err(anyhow!(
                    "Identity hash already exists as contact '{}'",
                    existing.name
                ));
            }
        }

        let name = contact.name.clone();
        self.contacts.insert(name, contact);
        self.save()?;

        Ok(())
    }

    /// Remove a contact by name.
    pub fn remove(&mut self, name: &str) -> Result<Contact> {
        self.contacts
            .remove(name)
            .ok_or_else(|| anyhow!("Contact '{}' not found", name))?;
        self.save()?;

        // Return a placeholder since we already removed it
        Err(anyhow!("Contact removed"))
    }

    /// Get a contact by name.
    pub fn get(&self, name: &str) -> Option<&Contact> {
        self.contacts.get(name)
    }

    /// Get a mutable contact by name.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut Contact> {
        self.contacts.get_mut(name)
    }

    /// List all contacts.
    pub fn list(&self) -> Vec<&Contact> {
        let mut contacts: Vec<_> = self.contacts.values().collect();
        contacts.sort_by(|a, b| a.name.cmp(&b.name));
        contacts
    }

    /// Mark a contact as verified.
    pub fn mark_verified(&mut self, name: &str) -> Result<()> {
        let contact = self
            .get_mut(name)
            .ok_or_else(|| anyhow!("Contact '{}' not found", name))?;
        contact.verified = true;
        self.save()
    }
}

// =============================================================================
// Message Queue (Simulated)
// =============================================================================

/// A message in the queue (for demonstration purposes).
#[derive(Clone, Debug)]
pub struct QueuedMessage {
    /// Message ID
    pub id: u64,

    /// Recipient name
    pub to: String,

    /// Message content
    pub content: String,

    /// Timestamp
    pub timestamp: i64,
}

/// Simple message queue for demonstration.
#[derive(Debug, Default)]
pub struct MessageQueue {
    /// Outgoing messages (simulated)
    outgoing: Vec<QueuedMessage>,

    /// Incoming messages (simulated)
    incoming: Vec<QueuedMessage>,

    /// Message counter
    counter: u64,
}

impl MessageQueue {
    /// Create a new message queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a message for sending.
    pub fn queue_outgoing(&mut self, to: String, content: String) -> u64 {
        self.counter += 1;
        let msg = QueuedMessage {
            id: self.counter,
            to,
            content,
            timestamp: chrono::Utc::now().timestamp(),
        };
        self.outgoing.push(msg);
        self.counter
    }

    /// Simulate receiving a message.
    #[allow(dead_code)]
    pub fn simulate_incoming(&mut self, from: String, content: String) {
        self.counter += 1;
        let msg = QueuedMessage {
            id: self.counter,
            to: from,
            content,
            timestamp: chrono::Utc::now().timestamp(),
        };
        self.incoming.push(msg);
    }

    /// Get pending outgoing messages.
    pub fn pending_outgoing(&self) -> &[QueuedMessage] {
        &self.outgoing
    }

    /// Get pending incoming messages.
    #[allow(dead_code)]
    pub fn pending_incoming(&self) -> &[QueuedMessage] {
        &self.incoming
    }
}

// =============================================================================
// CLI Application
// =============================================================================

/// The CLI chat application state.
pub struct ChatApp {
    /// VERITAS client instance
    client: VeritasClient,

    /// Contact storage
    contacts: Arc<RwLock<ContactStore>>,

    /// Message queue (simulated)
    messages: Arc<RwLock<MessageQueue>>,

    /// Data directory
    data_dir: PathBuf,

    /// Our identity keypair (for safety number computation)
    identity_keypair: Option<IdentityKeyPair>,
}

impl ChatApp {
    /// Create a new chat application.
    pub async fn new() -> Result<Self> {
        // Determine data directory
        let data_dir = Self::get_data_dir()?;
        info!("Using data directory: {:?}", data_dir);

        // Create VERITAS client with persistent storage
        let config = ClientConfig::builder()
            .with_data_dir(data_dir.clone())
            .build();

        let client = VeritasClient::new(config)
            .await
            .context("Failed to create VERITAS client")?;

        // Load contacts
        let contacts = ContactStore::load(&data_dir).context("Failed to load contacts")?;

        Ok(Self {
            client,
            contacts: Arc::new(RwLock::new(contacts)),
            messages: Arc::new(RwLock::new(MessageQueue::new())),
            data_dir,
            identity_keypair: None,
        })
    }

    /// Get the data directory for this application.
    fn get_data_dir() -> Result<PathBuf> {
        // Try platform-specific data directory
        if let Some(data_dir) = dirs::data_dir() {
            return Ok(data_dir.join(APP_NAME));
        }

        // Fall back to home directory
        if let Some(home_dir) = dirs::home_dir() {
            return Ok(home_dir.join(format!(".{}", APP_NAME)));
        }

        // Last resort: current directory
        Ok(PathBuf::from(format!(".{}", APP_NAME)))
    }

    /// Initialize the application (unlock and create identity if needed).
    pub async fn initialize(&mut self) -> Result<()> {
        print_info("Initializing VERITAS client...");

        // Unlock the client
        self.client
            .unlock(DEFAULT_PASSWORD)
            .await
            .context("Failed to unlock client")?;

        // Check if we have an identity, create one if not
        match self.client.identity_hash().await {
            Ok(hash) => {
                print_success(&format!("Loaded existing identity: {}", hash.short()));
            }
            Err(_) => {
                print_info("Creating new identity...");
                let hash = self
                    .client
                    .create_identity(Some("Primary"))
                    .await
                    .context("Failed to create identity")?;
                print_success(&format!("Created new identity: {}", hash.short()));
            }
        }

        // Generate a local keypair for safety number computation
        // (In a real app, this would come from the client)
        self.identity_keypair = Some(IdentityKeyPair::generate());

        Ok(())
    }

    /// Run the main application loop.
    pub async fn run(&mut self) -> Result<()> {
        print_header();
        print_help();

        let stdin = io::stdin();
        let mut stdout = io::stdout();

        loop {
            // Print prompt
            stdout.execute(SetForegroundColor(Color::Cyan))?;
            print!("> ");
            stdout.execute(ResetColor)?;
            stdout.flush()?;

            // Read input
            let mut input = String::new();
            stdin.lock().read_line(&mut input)?;
            let input = input.trim();

            // Skip empty lines
            if input.is_empty() {
                continue;
            }

            // Process command
            match self.process_command(input).await {
                Ok(should_quit) => {
                    if should_quit {
                        break;
                    }
                }
                Err(e) => {
                    print_error(&format!("Error: {}", e));
                }
            }
        }

        // Clean shutdown
        print_info("Shutting down...");
        self.client.lock().await?;

        Ok(())
    }

    /// Process a single command.
    async fn process_command(&mut self, input: &str) -> Result<bool> {
        // Parse command and arguments
        let parts: Vec<&str> = input.splitn(3, ' ').collect();
        let command = parts.first().copied().unwrap_or("");

        match command {
            "/help" | "/h" | "/?" => {
                print_help();
            }

            "/identity" | "/id" => {
                self.cmd_identity().await?;
            }

            "/contacts" | "/c" => {
                self.cmd_contacts().await?;
            }

            "/add" | "/a" => {
                if parts.len() < 3 {
                    return Err(anyhow!("Usage: /add <hash> <name>"));
                }
                let hash = parts[1];
                let name = parts[2];
                self.cmd_add_contact(hash, name).await?;
            }

            "/remove" | "/rm" => {
                if parts.len() < 2 {
                    return Err(anyhow!("Usage: /remove <name>"));
                }
                let name = parts[1];
                self.cmd_remove_contact(name).await?;
            }

            "/msg" | "/m" => {
                if parts.len() < 3 {
                    return Err(anyhow!("Usage: /msg <name> <message>"));
                }
                let name = parts[1];
                let message = parts[2];
                self.cmd_send_message(name, message).await?;
            }

            "/safety" | "/s" => {
                if parts.len() < 2 {
                    return Err(anyhow!("Usage: /safety <name>"));
                }
                let name = parts[1];
                self.cmd_safety_number(name).await?;
            }

            "/verify" | "/v" => {
                if parts.len() < 2 {
                    return Err(anyhow!("Usage: /verify <name>"));
                }
                let name = parts[1];
                self.cmd_verify_contact(name).await?;
            }

            "/status" => {
                self.cmd_status().await?;
            }

            "/quit" | "/q" | "/exit" => {
                print_info("Goodbye!");
                return Ok(true);
            }

            _ => {
                // Treat as a message if it doesn't start with /
                if !input.starts_with('/') {
                    print_warning("Use /msg <name> <message> to send a message");
                } else {
                    return Err(anyhow!(
                        "Unknown command: {}. Type /help for available commands.",
                        command
                    ));
                }
            }
        }

        Ok(false)
    }

    /// Show identity information.
    async fn cmd_identity(&self) -> Result<()> {
        let hash = self.client.identity_hash().await?;
        let public_keys = self.client.public_keys().await?;
        let slots = self.client.identity_slots().await?;

        println!();
        print_section("Your Identity");
        println!("  Hash:       {}", hash);
        println!("  Short:      {}", hash.short());
        println!(
            "  Exchange:   {} bytes",
            public_keys.exchange.as_bytes().len()
        );
        println!();
        print_section("Identity Slots");
        println!("  Used:       {}/{}", slots.used, slots.max);
        println!("  Available:  {}", slots.available);
        println!();

        Ok(())
    }

    /// List all contacts.
    async fn cmd_contacts(&self) -> Result<()> {
        let store = self.contacts.read().await;
        let contacts = store.list();

        println!();
        if contacts.is_empty() {
            print_info("No contacts yet. Use /add <hash> <name> to add one.");
        } else {
            print_section(&format!("Contacts ({})", contacts.len()));
            println!();
            for contact in contacts {
                let verified = if contact.verified { "[verified]" } else { "" };
                let mut stdout = io::stdout();

                stdout.execute(SetForegroundColor(Color::White))?;
                print!("  {}", contact.name);
                stdout.execute(ResetColor)?;

                if !verified.is_empty() {
                    stdout.execute(SetForegroundColor(Color::Green))?;
                    print!(" {}", verified);
                    stdout.execute(ResetColor)?;
                }
                println!();

                stdout.execute(SetForegroundColor(Color::DarkGrey))?;
                println!("    {}", contact.identity_hash);
                stdout.execute(ResetColor)?;
            }
        }
        println!();

        Ok(())
    }

    /// Add a new contact.
    async fn cmd_add_contact(&self, hash: &str, name: &str) -> Result<()> {
        // Validate the hash format
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow!(
                "Invalid identity hash. Expected 64 hex characters."
            ));
        }

        // Validate the name
        let name = name.trim();
        if name.is_empty() {
            return Err(anyhow!("Contact name cannot be empty"));
        }
        if name.len() > 32 {
            return Err(anyhow!("Contact name too long (max 32 characters)"));
        }

        // Create and add the contact
        let contact = Contact::new(name.to_string(), hash.to_lowercase());

        let mut store = self.contacts.write().await;
        store.add(contact)?;

        print_success(&format!("Added contact '{}'", name));

        Ok(())
    }

    /// Remove a contact.
    async fn cmd_remove_contact(&self, name: &str) -> Result<()> {
        let mut store = self.contacts.write().await;

        // Check if contact exists
        if store.get(name).is_none() {
            return Err(anyhow!("Contact '{}' not found", name));
        }

        store.contacts.remove(name);
        store.save()?;

        print_success(&format!("Removed contact '{}'", name));

        Ok(())
    }

    /// Send a message to a contact.
    async fn cmd_send_message(&self, name: &str, message: &str) -> Result<()> {
        // Validate message length
        if message.is_empty() {
            return Err(anyhow!("Message cannot be empty"));
        }
        if message.chars().count() > 300 {
            return Err(anyhow!(
                "Message too long ({} chars). Maximum is 300 characters.",
                message.chars().count()
            ));
        }

        // Find the contact
        let store = self.contacts.read().await;
        let contact = store
            .get(name)
            .ok_or_else(|| anyhow!("Contact '{}' not found", name))?;

        // Queue the message (simulated)
        let mut queue = self.messages.write().await;
        let msg_id = queue.queue_outgoing(name.to_string(), message.to_string());

        // In a real implementation, we would call:
        // self.client.send_message(&contact.identity()?, message, SendOptions::default()).await?;

        print_success(&format!(
            "Message queued (id: {}) to '{}': {}",
            msg_id,
            contact.name,
            truncate(message, 50)
        ));

        // Note about simulation
        print_warning("Note: Message sending is simulated in this demo.");

        Ok(())
    }

    /// Show safety number for a contact.
    async fn cmd_safety_number(&self, name: &str) -> Result<()> {
        // Find the contact
        let store = self.contacts.read().await;
        let contact = store
            .get(name)
            .ok_or_else(|| anyhow!("Contact '{}' not found", name))?;

        // Get our identity keypair
        let our_keypair = self
            .identity_keypair
            .as_ref()
            .ok_or_else(|| anyhow!("Identity not initialized"))?;

        // Generate a simulated keypair for the contact
        // (In a real app, we would have their actual public keys)
        let contact_keypair = IdentityKeyPair::generate();

        // Compute safety number
        let safety_number =
            SafetyNumber::compute(our_keypair.public_keys(), contact_keypair.public_keys());

        println!();
        print_section(&format!("Safety Number for '{}'", contact.name));
        println!();
        println!("  Compare this number with your contact:");
        println!();

        // Print safety number in a formatted way
        let numeric = safety_number.to_numeric_string();
        let groups: Vec<&str> = numeric.split(' ').collect();

        // Print in 3 rows of 4 groups
        let mut stdout = io::stdout();
        for row in 0..3 {
            print!("    ");
            for col in 0..4 {
                let idx = row * 4 + col;
                if idx < groups.len() {
                    stdout.execute(SetForegroundColor(Color::Yellow))?;
                    print!("{}", groups[idx]);
                    stdout.execute(ResetColor)?;
                    if col < 3 {
                        print!("  ");
                    }
                }
            }
            println!();
        }
        stdout.execute(ResetColor)?;
        println!();

        // Show QR code data
        print_section("QR Code Data");
        println!("  {}", safety_number.to_qr_string());
        println!();

        // Verification status
        if contact.verified {
            print_success("This contact has been marked as verified.");
        } else {
            print_info("Use /verify <name> to mark this contact as verified.");
        }
        println!();

        // Security note
        print_warning("Note: Safety numbers are simulated in this demo.");
        print_warning("In production, compare these numbers in person or via a trusted channel.");

        Ok(())
    }

    /// Mark a contact as verified.
    async fn cmd_verify_contact(&self, name: &str) -> Result<()> {
        let mut store = self.contacts.write().await;
        store.mark_verified(name)?;
        print_success(&format!("Contact '{}' marked as verified", name));

        Ok(())
    }

    /// Show application status.
    async fn cmd_status(&self) -> Result<()> {
        let state = self.client.state().await;
        let store = self.contacts.read().await;
        let queue = self.messages.read().await;

        println!();
        print_section("Application Status");
        println!("  Client State:     {}", state);
        println!("  Data Directory:   {:?}", self.data_dir);
        println!("  Contacts:         {}", store.list().len());
        println!("  Pending Messages: {}", queue.pending_outgoing().len());
        println!();

        Ok(())
    }
}

// =============================================================================
// Terminal Output Helpers
// =============================================================================

/// Print the application header.
fn print_header() {
    let mut stdout = io::stdout();
    println!();
    let _ = stdout.execute(SetForegroundColor(Color::Cyan));
    println!(
        r#"
 __     _______ ____  ___ _____  _    ____
 \ \   / / ____|  _ \|_ _|_   _|/ \  / ___|
  \ \ / /|  _| | |_) || |  | | / _ \ \___ \
   \ V / | |___|  _ < | |  | |/ ___ \ ___) |
    \_/  |_____|_| \_\___| |_/_/   \_\____/

"#
    );
    let _ = stdout.execute(ResetColor);
    println!("  VERITAS CLI Chat - Post-Quantum Secure Messaging");
    println!("  Version 0.1.0");
    println!();
}

/// Print help information.
fn print_help() {
    let mut stdout = io::stdout();

    println!();
    let _ = stdout.execute(SetForegroundColor(Color::White));
    println!("Available Commands:");
    let _ = stdout.execute(ResetColor);
    println!();

    let commands = [
        ("/identity, /id", "Show your identity hash and public keys"),
        ("/contacts, /c", "List all contacts"),
        ("/add <hash> <name>", "Add a new contact by identity hash"),
        ("/remove <name>", "Remove a contact"),
        ("/msg <name> <message>", "Send a message to a contact"),
        (
            "/safety <name>",
            "Show safety number for contact verification",
        ),
        ("/verify <name>", "Mark a contact as verified"),
        ("/status", "Show application status"),
        ("/help, /h", "Show this help message"),
        ("/quit, /q", "Exit the application"),
    ];

    for (cmd, desc) in commands {
        let _ = stdout.execute(SetForegroundColor(Color::Yellow));
        print!("  {:<25}", cmd);
        let _ = stdout.execute(ResetColor);
        println!(" {}", desc);
    }
    println!();
}

/// Print a section header.
fn print_section(title: &str) {
    let mut stdout = io::stdout();
    let _ = stdout.execute(SetForegroundColor(Color::White));
    println!("{}", title);
    println!("{}", "-".repeat(title.len()));
    let _ = stdout.execute(ResetColor);
}

/// Print an info message.
fn print_info(message: &str) {
    let mut stdout = io::stdout();
    let _ = stdout.execute(SetForegroundColor(Color::Blue));
    print!("[INFO] ");
    let _ = stdout.execute(ResetColor);
    println!("{}", message);
}

/// Print a success message.
fn print_success(message: &str) {
    let mut stdout = io::stdout();
    let _ = stdout.execute(SetForegroundColor(Color::Green));
    print!("[OK] ");
    let _ = stdout.execute(ResetColor);
    println!("{}", message);
}

/// Print an error message.
fn print_error(message: &str) {
    let mut stdout = io::stdout();
    let _ = stdout.execute(SetForegroundColor(Color::Red));
    print!("[ERROR] ");
    let _ = stdout.execute(ResetColor);
    println!("{}", message);
}

/// Print a warning message.
fn print_warning(message: &str) {
    let mut stdout = io::stdout();
    let _ = stdout.execute(SetForegroundColor(Color::Yellow));
    print!("[WARN] ");
    let _ = stdout.execute(ResetColor);
    println!("{}", message);
}

/// Truncate a string with ellipsis if too long.
fn truncate(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        format!("{}...", s.chars().take(max_len - 3).collect::<String>())
    }
}

// =============================================================================
// Main Entry Point
// =============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging with simple output
    // Set RUST_LOG=debug for verbose output
    tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(tracing::Level::WARN)
        .init();

    // Create and initialize the chat application
    let mut app = ChatApp::new().await?;

    // Initialize (unlock client, create identity if needed)
    app.initialize().await?;

    // Run the main loop
    app.run().await?;

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contact_creation() {
        let hash = "a".repeat(64);
        let contact = Contact::new("Alice".to_string(), hash.clone());

        assert_eq!(contact.name, "Alice");
        assert_eq!(contact.identity_hash, hash);
        assert!(!contact.verified);
    }

    #[test]
    fn test_truncate_short_string() {
        let s = "Hello";
        assert_eq!(truncate(s, 10), "Hello");
    }

    #[test]
    fn test_truncate_long_string() {
        let s = "Hello, World! This is a long message.";
        assert_eq!(truncate(s, 15), "Hello, World...");
    }

    #[test]
    fn test_contact_identity_valid() {
        let hash = "a".repeat(64);
        let contact = Contact::new("Test".to_string(), hash);
        assert!(contact.identity().is_ok());
    }

    #[test]
    fn test_contact_identity_invalid() {
        let contact = Contact::new("Test".to_string(), "invalid".to_string());
        assert!(contact.identity().is_err());
    }

    #[test]
    fn test_message_queue() {
        let mut queue = MessageQueue::new();

        let id1 = queue.queue_outgoing("Alice".to_string(), "Hello".to_string());
        let id2 = queue.queue_outgoing("Bob".to_string(), "Hi".to_string());

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(queue.pending_outgoing().len(), 2);
    }
}

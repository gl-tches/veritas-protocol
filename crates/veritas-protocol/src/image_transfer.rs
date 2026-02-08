//! P2P image transfer with on-chain proof (AD-6).
//!
//! Images are transferred peer-to-peer (direct connection), NOT on-chain.
//! Only a proof/receipt goes on-chain (image hash + delivery confirmation).
//!
//! ## Privacy Warning
//!
//! P2P image transfer requires a direct connection between sender and recipient,
//! which may reveal IP addresses. Users MUST be warned and must explicitly
//! acknowledge this risk before proceeding.
//!
//! ## Flow
//!
//! 1. Sender initiates image transfer request
//! 2. System displays privacy warning about IP exposure
//! 3. User explicitly acknowledges the warning
//! 4. P2P connection is established
//! 5. Image is transferred with E2E encryption
//! 6. On-chain proof is created (BLAKE3 hash + delivery receipt)
//! 7. On-chain proof follows epoch pruning rules

use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;

/// Privacy warning message displayed before P2P image transfer.
pub const IMAGE_TRANSFER_WARNING: &str =
    "P2P image transfer may reveal your IP address to the recipient. \
     This direct connection bypasses the chain's anonymity protections. \
     Only proceed if you trust the recipient with your network identity.";

/// Short warning for display in constrained UIs.
pub const IMAGE_TRANSFER_WARNING_SHORT: &str =
    "P2P transfer may reveal your IP address to the recipient.";

/// Maximum image size in bytes (10 MB).
pub const MAX_IMAGE_SIZE: usize = 10 * 1024 * 1024;

/// Supported image content types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageContentType {
    /// JPEG image.
    Jpeg,
    /// PNG image.
    Png,
    /// WebP image.
    WebP,
    /// GIF image (static only).
    Gif,
}

impl ImageContentType {
    /// Get the MIME type string.
    pub fn mime_type(&self) -> &'static str {
        match self {
            ImageContentType::Jpeg => "image/jpeg",
            ImageContentType::Png => "image/png",
            ImageContentType::WebP => "image/webp",
            ImageContentType::Gif => "image/gif",
        }
    }

    /// Detect content type from file extension.
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "jpg" | "jpeg" => Some(ImageContentType::Jpeg),
            "png" => Some(ImageContentType::Png),
            "webp" => Some(ImageContentType::WebP),
            "gif" => Some(ImageContentType::Gif),
            _ => None,
        }
    }
}

/// An image transfer request.
///
/// Represents a pending image transfer that requires user acknowledgment
/// of the privacy warning before proceeding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageTransferRequest {
    /// BLAKE3 hash of the image content.
    pub image_hash: Hash256,
    /// Size of the image in bytes.
    pub image_size: usize,
    /// Content type of the image.
    pub content_type: ImageContentType,
    /// Whether the user has acknowledged the privacy warning.
    warning_acknowledged: bool,
}

impl ImageTransferRequest {
    /// Create a new image transfer request.
    ///
    /// The request starts with the warning NOT acknowledged.
    /// Call `acknowledge_warning()` after the user explicitly confirms.
    ///
    /// # Arguments
    ///
    /// * `image_data` - The raw image bytes (used to compute hash)
    /// * `content_type` - The image content type
    ///
    /// # Errors
    ///
    /// Returns an error if the image exceeds MAX_IMAGE_SIZE.
    pub fn new(image_data: &[u8], content_type: ImageContentType) -> Result<Self, ImageTransferError> {
        if image_data.len() > MAX_IMAGE_SIZE {
            return Err(ImageTransferError::ImageTooLarge {
                size: image_data.len(),
                max: MAX_IMAGE_SIZE,
            });
        }

        if image_data.is_empty() {
            return Err(ImageTransferError::EmptyImage);
        }

        let image_hash = Hash256::hash(image_data);

        Ok(Self {
            image_hash,
            image_size: image_data.len(),
            content_type,
            warning_acknowledged: false,
        })
    }

    /// Acknowledge the privacy warning.
    ///
    /// This MUST be called after the user has explicitly confirmed they
    /// understand the privacy implications of P2P image transfer.
    pub fn acknowledge_warning(&mut self) {
        self.warning_acknowledged = true;
    }

    /// Check if the privacy warning has been acknowledged.
    pub fn is_warning_acknowledged(&self) -> bool {
        self.warning_acknowledged
    }

    /// Check if this request is ready to proceed.
    ///
    /// A request is ready when the warning has been acknowledged.
    pub fn is_ready(&self) -> bool {
        self.warning_acknowledged
    }

    /// Get the privacy warning text.
    pub fn warning_text(&self) -> &'static str {
        IMAGE_TRANSFER_WARNING
    }

    /// Get the short privacy warning text.
    pub fn warning_text_short(&self) -> &'static str {
        IMAGE_TRANSFER_WARNING_SHORT
    }
}

/// On-chain proof for a completed image transfer.
///
/// This is the only part that goes on-chain. The image itself is
/// transferred P2P and never touches the blockchain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImageTransferProof {
    /// BLAKE3 hash of the image content.
    pub image_hash: Hash256,
    /// BLAKE3 hash of the delivery receipt.
    pub receipt_hash: Hash256,
    /// Timestamp bucket (same bucketing as messages for privacy).
    pub timestamp_bucket: u64,
    /// Size of the image in bytes (for validation).
    pub image_size: u32,
}

impl ImageTransferProof {
    /// Create a new image transfer proof.
    ///
    /// # Arguments
    ///
    /// * `image_hash` - BLAKE3 hash of the image
    /// * `receipt_data` - The delivery receipt bytes (hashed for on-chain storage)
    /// * `image_size` - Size of the original image
    pub fn new(image_hash: Hash256, receipt_data: &[u8], image_size: u32) -> Self {
        let receipt_hash = Hash256::hash(receipt_data);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs();

        // Use hourly timestamp bucketing (same as gossip)
        let timestamp_bucket = now / 3600;

        Self {
            image_hash,
            receipt_hash,
            timestamp_bucket,
            image_size,
        }
    }

    /// Verify that a proof matches a given image hash.
    pub fn verify_image(&self, image_data: &[u8]) -> bool {
        let computed = Hash256::hash(image_data);
        self.image_hash == computed
    }
}

/// Errors specific to image transfer.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ImageTransferError {
    /// Image exceeds maximum size.
    #[error("image too large: {size} bytes (max: {max})")]
    ImageTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Image data is empty.
    #[error("image data is empty")]
    EmptyImage,

    /// Privacy warning not acknowledged.
    #[error("privacy warning must be acknowledged before transfer")]
    WarningNotAcknowledged,

    /// Transfer failed.
    #[error("image transfer failed: {0}")]
    TransferFailed(String),
}

/// Validate that an image transfer can proceed.
///
/// # Security
///
/// This function enforces the privacy warning acknowledgment requirement.
/// It MUST be called before initiating any P2P image transfer.
pub fn validate_transfer_request(request: &ImageTransferRequest) -> Result<(), ImageTransferError> {
    if !request.is_warning_acknowledged() {
        return Err(ImageTransferError::WarningNotAcknowledged);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_image_transfer_request_creation() {
        let image_data = vec![0xFF_u8; 1024]; // 1KB fake image
        let request = ImageTransferRequest::new(&image_data, ImageContentType::Jpeg).unwrap();

        assert!(!request.is_warning_acknowledged());
        assert!(!request.is_ready());
        assert_eq!(request.image_size, 1024);
        assert_eq!(request.content_type, ImageContentType::Jpeg);
    }

    #[test]
    fn test_warning_acknowledgment_flow() {
        let image_data = vec![0xFF_u8; 1024];
        let mut request = ImageTransferRequest::new(&image_data, ImageContentType::Png).unwrap();

        // Not acknowledged yet
        assert!(!request.is_warning_acknowledged());
        assert!(validate_transfer_request(&request).is_err());

        // Acknowledge
        request.acknowledge_warning();
        assert!(request.is_warning_acknowledged());
        assert!(request.is_ready());
        assert!(validate_transfer_request(&request).is_ok());
    }

    #[test]
    fn test_image_too_large() {
        let image_data = vec![0xFF_u8; MAX_IMAGE_SIZE + 1];
        let result = ImageTransferRequest::new(&image_data, ImageContentType::Jpeg);
        assert!(matches!(result, Err(ImageTransferError::ImageTooLarge { .. })));
    }

    #[test]
    fn test_empty_image() {
        let result = ImageTransferRequest::new(&[], ImageContentType::Jpeg);
        assert!(matches!(result, Err(ImageTransferError::EmptyImage)));
    }

    #[test]
    fn test_image_transfer_proof() {
        let image_data = b"fake image data for testing";
        let receipt_data = b"delivery receipt";

        let proof = ImageTransferProof::new(
            Hash256::hash(image_data),
            receipt_data,
            image_data.len() as u32,
        );

        assert!(proof.verify_image(image_data));
        assert!(!proof.verify_image(b"different data"));
    }

    #[test]
    fn test_warning_text_not_empty() {
        let image_data = vec![0xFF_u8; 100];
        let request = ImageTransferRequest::new(&image_data, ImageContentType::Jpeg).unwrap();

        assert!(!request.warning_text().is_empty());
        assert!(!request.warning_text_short().is_empty());
        assert!(request.warning_text().contains("IP address"));
    }

    #[test]
    fn test_content_type_mime() {
        assert_eq!(ImageContentType::Jpeg.mime_type(), "image/jpeg");
        assert_eq!(ImageContentType::Png.mime_type(), "image/png");
        assert_eq!(ImageContentType::WebP.mime_type(), "image/webp");
        assert_eq!(ImageContentType::Gif.mime_type(), "image/gif");
    }

    #[test]
    fn test_content_type_from_extension() {
        assert_eq!(
            ImageContentType::from_extension("jpg"),
            Some(ImageContentType::Jpeg)
        );
        assert_eq!(
            ImageContentType::from_extension("JPEG"),
            Some(ImageContentType::Jpeg)
        );
        assert_eq!(
            ImageContentType::from_extension("png"),
            Some(ImageContentType::Png)
        );
        assert_eq!(ImageContentType::from_extension("txt"), None);
    }

    #[test]
    fn test_image_at_max_size() {
        let image_data = vec![0xFF_u8; MAX_IMAGE_SIZE];
        let result = ImageTransferRequest::new(&image_data, ImageContentType::Jpeg);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_transfer_request_requires_ack() {
        let image_data = vec![0xFF_u8; 100];
        let request = ImageTransferRequest::new(&image_data, ImageContentType::Jpeg).unwrap();

        let err = validate_transfer_request(&request).unwrap_err();
        assert!(matches!(err, ImageTransferError::WarningNotAcknowledged));
    }
}

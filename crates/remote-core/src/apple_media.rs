//! What the Mac's media path is doing, as reported by its answer.

/// The state of the media path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaState {
    /// The canvas the encoder renders, in pixels.
    pub canvas_width: u32,
    pub canvas_height: u32,
    /// The size of the Mac's desktop, in points.
    pub desktop_width: u32,
    pub desktop_height: u32,
    /// The size of the picture that is actually arriving, in pixels.
    pub picture_width: u32,
    pub picture_height: u32,
    /// How many tile streams the video is split into.
    pub tiles: u32,
    /// The number of pictures that have been decoded since the session
    /// started.
    pub pictures: u64,
    /// The number of packets that went missing.
    pub lost: u64,
    /// The number of times the picture was asked for again.
    pub recoveries: u64,
}

impl MediaState {
    /// Whether the Mac is sending a picture that can be shown.
    pub fn is_streaming(&self) -> bool {
        self.canvas_width > 0 && self.canvas_height > 0 && self.pictures > 0
    }
}

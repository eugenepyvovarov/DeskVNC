//! What the Mac's media path is doing, as reported by its answer.

/// The state of the media path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MediaState {
    /// Canvas advertised in the media answer, not measured decoder output.
    pub canvas_width: u32,
    pub canvas_height: u32,
    /// The size of the Mac's desktop, in points.
    pub desktop_width: u32,
    pub desktop_height: u32,
    /// Pixel geometry from the latest display layout.
    pub layout_width: u32,
    pub layout_height: u32,
    /// Latest requested pixel geometry; not confirmation of application.
    pub requested_width: u32,
    pub requested_height: u32,
    /// How many tile streams the video is split into.
    pub tiles: u32,
    /// Access units assembled by the backend, not decoded/presented frames.
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

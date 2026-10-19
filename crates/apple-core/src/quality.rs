//! Server-side quality for Apple Screen Sharing, the Apple Remote Desktop way:
//! the preset selects the resolution the Mac renders and streams. `ScaleFactor`
//! (0x08) was live-tested and does not resize the H.264 path, so a smaller
//! canvas is the one server-side lever that actually reduces bandwidth.
use remote_core::QualityPreset;

/// The canvas each preset asks the Mac for. `native` is the geometry the
/// session started with; High/Auto keep it. A preset never asks for MORE
/// than native, and preserves native's aspect: the target is native scaled
/// to fit inside the preset's cap box, so presets are strictly monotonic
/// (Low ≤ Medium ≤ High = native) whatever the display's shape.
pub fn resolution_for(preset: QualityPreset, native: (u16, u16)) -> (u16, u16) {
    let (cap_w, cap_h) = match preset {
        QualityPreset::Low | QualityPreset::BlackAndWhite => (1920u32, 1080u32),
        QualityPreset::Medium => (2560, 1440),
        QualityPreset::High | QualityPreset::Auto => return native,
    };
    let (nw, nh) = (u32::from(native.0), u32::from(native.1));
    if nw == 0 || nh == 0 {
        return native;
    }
    let scale = (f64::from(cap_w) / f64::from(nw)).min(f64::from(cap_h) / f64::from(nh));
    if scale >= 1.0 {
        return native; // native already fits the cap: never upscale
    }
    (
        even((f64::from(nw) * scale).round() as u32).clamp(640, 3840) as u16,
        even((f64::from(nh) * scale).round() as u32).clamp(480, 2160) as u16,
    )
}

/// Round a dimension down to an even number.
///
/// H.264 4:2:0 samples chroma at half resolution in both directions, so an
/// odd width or height leaves a chroma sample that belongs to no pixel. The
/// encoder pads the picture to a whole macroblock, and the viewer then has
/// to crop it back to a size the chroma plane divides evenly. Asking for an
/// even size in the first place avoids the crop.
fn even(value: u32) -> u32 {
    value & !1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_map_to_smaller_server_canvases() {
        let native = (3600, 2338);
        assert_eq!(resolution_for(QualityPreset::Auto, native), native);
        assert_eq!(resolution_for(QualityPreset::High, native), native);
        // Aspect preserved (3600/2338 ≈ 1.54, not 16:9), capped, monotonic.
        let medium = resolution_for(QualityPreset::Medium, native);
        let low = resolution_for(QualityPreset::Low, native);
        assert!(low.0 <= medium.0 && medium.0 <= native.0, "{low:?} {medium:?}");
        assert!(low.1 <= medium.1 && medium.1 <= native.1, "{low:?} {medium:?}");
        assert_eq!(medium, (2216, 1440));
        assert_eq!(low, (1662, 1080));
        // Even dimensions, so the chroma plane divides evenly.
        assert_eq!(medium.0 % 2, 0);
        assert_eq!(low.0 % 2, 0);
    }

    #[test]
    fn presets_never_upscale_a_small_native() {
        // A Mac already at or below the cap stays exactly where it is.
        assert_eq!(resolution_for(QualityPreset::Low, (1280, 720)), (1280, 720));
        assert_eq!(resolution_for(QualityPreset::Medium, (1920, 1080)), (1920, 1080));
        assert_eq!(resolution_for(QualityPreset::Low, (0, 0)), (0, 0));
    }
}

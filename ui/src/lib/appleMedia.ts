/** Backend control/assembly telemetry. None of these fields proves presentation. */
export interface AppleMediaState {
  requestedWidth: number;
  requestedHeight: number;
  layoutWidth: number;
  layoutHeight: number;
  desktopWidth: number;
  desktopHeight: number;
  canvasWidth: number;
  canvasHeight: number;
  tiles: number;
  pictures: number;
  lost: number;
  recoveries: number;
}

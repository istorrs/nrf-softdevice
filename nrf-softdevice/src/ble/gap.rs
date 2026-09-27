use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU8, Ordering};

use crate::ble::*;
use crate::util::get_union_field;
use crate::{raw, RawError};

type LescDhkeyFn = fn(peer_pk: &[u8; 64]) -> Option<[u8; 32]>;

// PHY update observability. Both `BLE_GAP_EVT_PHY_UPDATE_REQUEST` and
// `BLE_GAP_EVT_PHY_UPDATE` fire from this module's `on_evt`, which runs in
// the SoftDevice's own event-processing context -- not the application task
// that owns a connection's `Terminal`/UART, so there is no way to log or act
// on these from application code without some cross-context handoff. A
// lock-free one-shot flag pair (set here, consumed by `take_*` below) avoids
// any lock or blocking call from this context, matching how every other
// SoftDevice-callback-to-application handoff in this crate's consumer works.
//
// One-shot: each `take_*` clears the flag it reads. A second event of the
// same kind arriving before the first is consumed overwrites the recorded
// fields with no queue -- acceptable here since these are diagnostic, not
// data that must not be dropped, and a PHY renegotiation is a rare event to
// begin with.
static PHY_UPDATE_REQUEST_PENDING: AtomicBool = AtomicBool::new(false);
static PHY_UPDATE_REQUEST_CONN: AtomicU16 = AtomicU16::new(0);
static PHY_UPDATE_REQUEST_RX: AtomicU8 = AtomicU8::new(0);
static PHY_UPDATE_REQUEST_TX: AtomicU8 = AtomicU8::new(0);

static PHY_UPDATE_PENDING: AtomicBool = AtomicBool::new(false);
static PHY_UPDATE_CONN: AtomicU16 = AtomicU16::new(0);
static PHY_UPDATE_STATUS: AtomicU8 = AtomicU8::new(0);
static PHY_UPDATE_RX: AtomicU8 = AtomicU8::new(0);
static PHY_UPDATE_TX: AtomicU8 = AtomicU8::new(0);

/// Consume the most recent peer-initiated PHY update request, if one arrived
/// since the last call, as `(conn_handle, rx_phys, tx_phys)` raw
/// `BLE_GAP_PHYS` bitmasks. By the time this is observable the SoftDevice has
/// already auto-accepted the request by echoing the peer's preferred masks
/// straight back (see the `BLE_GAP_EVT_PHY_UPDATE_REQUEST` arm below) --
/// there is currently no application hook to reject one. This function is
/// purely so the fact that a request happened, and what it asked for, isn't
/// silently invisible to application code.
pub fn take_phy_update_request() -> Option<(u16, u8, u8)> {
    if PHY_UPDATE_REQUEST_PENDING.swap(false, Ordering::Relaxed) {
        Some((
            PHY_UPDATE_REQUEST_CONN.load(Ordering::Relaxed),
            PHY_UPDATE_REQUEST_RX.load(Ordering::Relaxed),
            PHY_UPDATE_REQUEST_TX.load(Ordering::Relaxed),
        ))
    } else {
        None
    }
}

/// Consume the most recent PHY update completion, if one arrived since the
/// last call, as `(conn_handle, status, rx_phy, tx_phy)`. Fires regardless of
/// which side initiated the change. `status` is the raw GAP/HCI status byte
/// (0 = success); `rx_phy`/`tx_phy` are single-bit `BLE_GAP_PHYS` values, not
/// the request's preference masks.
pub fn take_phy_update() -> Option<(u16, u8, u8, u8)> {
    if PHY_UPDATE_PENDING.swap(false, Ordering::Relaxed) {
        Some((
            PHY_UPDATE_CONN.load(Ordering::Relaxed),
            PHY_UPDATE_STATUS.load(Ordering::Relaxed),
            PHY_UPDATE_RX.load(Ordering::Relaxed),
            PHY_UPDATE_TX.load(Ordering::Relaxed),
        ))
    } else {
        None
    }
}

// Link Layer Data Length Update observability -- same reasoning and pattern
// as the PHY-update flags above. `ConnectionState.data_length_effective`
// already exists internally (set from `BLE_GAP_EVT_DATA_LENGTH_UPDATE`,
// `connection.rs`), but only keeps `max_tx_octets` truncated to `u8`, and
// there is no public accessor for it at all -- application code cannot read
// it, and what it could read would already have thrown away rx_octets and
// both timing fields. These flags carry the full four-field
// `ble_gap_data_length_params_t` for both the request and the completion.
static DLE_REQUEST_PENDING: AtomicBool = AtomicBool::new(false);
static DLE_REQUEST_CONN: AtomicU16 = AtomicU16::new(0);
static DLE_REQUEST_TX_OCTETS: AtomicU16 = AtomicU16::new(0);
static DLE_REQUEST_RX_OCTETS: AtomicU16 = AtomicU16::new(0);
static DLE_REQUEST_TX_TIME_US: AtomicU16 = AtomicU16::new(0);
static DLE_REQUEST_RX_TIME_US: AtomicU16 = AtomicU16::new(0);

static DLE_UPDATE_PENDING: AtomicBool = AtomicBool::new(false);
static DLE_UPDATE_CONN: AtomicU16 = AtomicU16::new(0);
static DLE_UPDATE_TX_OCTETS: AtomicU16 = AtomicU16::new(0);
static DLE_UPDATE_RX_OCTETS: AtomicU16 = AtomicU16::new(0);
static DLE_UPDATE_TX_TIME_US: AtomicU16 = AtomicU16::new(0);
static DLE_UPDATE_RX_TIME_US: AtomicU16 = AtomicU16::new(0);

/// Consume the most recent peer-initiated Data Length Update request, if one
/// arrived since the last call, as `(conn_handle, tx_octets, rx_octets,
/// tx_time_us, rx_time_us)` -- the peer's requested Link Layer PDU
/// parameters. By the time this is observable the SoftDevice has already
/// auto-accepted it with `data_length_update(None)` (see the
/// `BLE_GAP_EVT_DATA_LENGTH_UPDATE_REQUEST` arm below); this is purely so
/// the request and what it asked for isn't silently invisible.
pub fn take_data_length_update_request() -> Option<(u16, u16, u16, u16, u16)> {
    if DLE_REQUEST_PENDING.swap(false, Ordering::Relaxed) {
        Some((
            DLE_REQUEST_CONN.load(Ordering::Relaxed),
            DLE_REQUEST_TX_OCTETS.load(Ordering::Relaxed),
            DLE_REQUEST_RX_OCTETS.load(Ordering::Relaxed),
            DLE_REQUEST_TX_TIME_US.load(Ordering::Relaxed),
            DLE_REQUEST_RX_TIME_US.load(Ordering::Relaxed),
        ))
    } else {
        None
    }
}

/// Consume the most recent Data Length Update completion, if one arrived
/// since the last call, as `(conn_handle, tx_octets, rx_octets, tx_time_us,
/// rx_time_us)` -- the negotiated *effective* Link Layer PDU parameters now
/// in force. Fires regardless of which side initiated the change.
pub fn take_data_length_update() -> Option<(u16, u16, u16, u16, u16)> {
    if DLE_UPDATE_PENDING.swap(false, Ordering::Relaxed) {
        Some((
            DLE_UPDATE_CONN.load(Ordering::Relaxed),
            DLE_UPDATE_TX_OCTETS.load(Ordering::Relaxed),
            DLE_UPDATE_RX_OCTETS.load(Ordering::Relaxed),
            DLE_UPDATE_TX_TIME_US.load(Ordering::Relaxed),
            DLE_UPDATE_RX_TIME_US.load(Ordering::Relaxed),
        ))
    } else {
        None
    }
}

// Safety for both statics: nrf-softdevice targets single-core Cortex-M only.
// set_lesc_dhkey_fn / set_lesc_own_pk are called from application context before any bonding
// begins and are never modified again.  The handler reads them from the SoftDevide interrupt.
// No concurrent write/write or torn-read is possible on this architecture.
static mut LESC_DHKEY_FN: Option<LescDhkeyFn> = None;
static mut LESC_OWN_PK_BUF: raw::ble_gap_lesc_p256_pk_t = raw::ble_gap_lesc_p256_pk_t { pk: [0u8; 64] };

/// Register a callback that computes the LESC Diffie-Hellman shared secret.
/// Called when `BLE_GAP_EVT_LESC_DHKEY_REQUEST` fires.
/// Receives the peer's P-256 public key as 64 bytes {X, Y} in little-endian.
/// Returns the 32-byte x-coordinate of the shared secret in little-endian, or `None` to abort.
///
/// # Safety
/// Must be called before the first bonding attempt and not changed afterwards.
pub unsafe fn set_lesc_dhkey_fn(f: LescDhkeyFn) {
    LESC_DHKEY_FN = Some(f);
}

/// Store our LESC P-256 public key (64 bytes, {X_LE, Y_LE}) so it can be supplied as
/// `keys_own.p_pk` in `sd_ble_gap_sec_params_reply`.  Call before `sd_ble_gap_authenticate`.
///
/// # Safety
/// Must be called before the first bonding attempt and not changed concurrently with bonding.
pub unsafe fn set_lesc_own_pk(pk_le: [u8; 64]) {
    LESC_OWN_PK_BUF.pk = pk_le;
}

pub(crate) unsafe fn on_evt(ble_evt: *const raw::ble_evt_t) {
    let gap_evt = get_union_field(ble_evt, &(*ble_evt).evt.gap_evt);
    match (*ble_evt).header.evt_id as u32 {
        raw::BLE_GAP_EVTS_BLE_GAP_EVT_CONNECTED => {
            let params = &gap_evt.params.connected;

            debug!(
                "conn_params conn_sup_timeout={:?} max_conn_interval={:?} min_conn_interval={:?} slave_latency={:?}",
                params.conn_params.conn_sup_timeout,
                params.conn_params.max_conn_interval,
                params.conn_params.min_conn_interval,
                params.conn_params.slave_latency,
            );

            let handled = match Role::from_raw(params.role) {
                #[cfg(feature = "ble-central")]
                Role::Central => central::CONNECT_PORTAL.call(ble_evt),
                #[cfg(feature = "ble-peripheral")]
                Role::Peripheral => peripheral::ADV_PORTAL.call(ble_evt),
            };
            if !handled {
                raw::sd_ble_gap_disconnect(gap_evt.conn_handle, raw::BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION as _);
            }
        }
        raw::BLE_GAP_EVTS_BLE_GAP_EVT_DISCONNECTED => {
            trace!("on_disconnected conn_handle={:?}", gap_evt.conn_handle);
            connection::with_state_by_conn_handle(gap_evt.conn_handle, |state| state.on_disconnected(ble_evt));
        }
        raw::BLE_GAP_EVTS_BLE_GAP_EVT_CONN_PARAM_UPDATE => {
            let conn_params = gap_evt.params.conn_param_update.conn_params;

            debug!(
                "on_conn_param_update conn_handle={:?} conn_sup_timeout={:?} max_conn_interval={:?} min_conn_interval={:?} slave_latency={:?}",
                gap_evt.conn_handle,
                conn_params.conn_sup_timeout,
                conn_params.max_conn_interval,
                conn_params.min_conn_interval,
                conn_params.slave_latency,
            );

            connection::with_state_by_conn_handle(gap_evt.conn_handle, |state| {
                state.conn_params = conn_params;
            });
        }
        #[cfg(feature = "ble-central")]
        raw::BLE_GAP_EVTS_BLE_GAP_EVT_CONN_PARAM_UPDATE_REQUEST => {
            let conn_handle = gap_evt.conn_handle;
            let conn_params = gap_evt.params.conn_param_update_request.conn_params;
            debug!(
                "on_conn_param_update_request conn_handle={:?} conn_sup_timeout={:?} max_conn_interval={:?} min_conn_interval={:?} slave_latency={:?}",
                gap_evt.conn_handle,
                conn_params.conn_sup_timeout,
                conn_params.max_conn_interval,
                conn_params.min_conn_interval,
                conn_params.slave_latency,
            );

            let ret = raw::sd_ble_gap_conn_param_update(conn_handle, &conn_params);
            if let Err(err) = RawError::convert(ret) {
                warn!("sd_ble_gap_conn_param_update err {:?}", err);
            }
        }
        raw::BLE_GAP_EVTS_BLE_GAP_EVT_TIMEOUT => {
            trace!("on_timeout conn_handle={:?}", gap_evt.conn_handle);

            let params = &gap_evt.params.timeout;
            match params.src as u32 {
                #[cfg(feature = "ble-central")]
                raw::BLE_GAP_TIMEOUT_SRC_CONN => {
                    central::CONNECT_PORTAL.call(ble_evt);
                }
                #[cfg(feature = "ble-central")]
                raw::BLE_GAP_TIMEOUT_SRC_SCAN => {
                    central::SCAN_PORTAL.call(ble_evt);
                }
                raw::BLE_GAP_TIMEOUT_SRC_AUTH_PAYLOAD => {
                    // Authenticated payload timeout on an encrypted connection.
                    // Disconnect so futures waiting on this connection (e.g. gatt_client::run)
                    // receive BLE_GAP_EVT_DISCONNECTED and can clean up gracefully.
                    warn!("auth payload timeout conn_handle={:?}", gap_evt.conn_handle);
                    raw::sd_ble_gap_disconnect(
                        gap_evt.conn_handle,
                        raw::BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION as u8,
                    );
                }
                x => warn!("unknown timeout src {:?}", x),
            };
        }
        #[cfg(feature = "ble-peripheral")]
        raw::BLE_GAP_EVTS_BLE_GAP_EVT_ADV_SET_TERMINATED => {
            trace!("adv_set_termnated");
            peripheral::ADV_PORTAL.call(ble_evt);
        }
        #[cfg(feature = "ble-central")]
        raw::BLE_GAP_EVTS_BLE_GAP_EVT_ADV_REPORT => {
            trace!("central on_adv_report");
            central::SCAN_PORTAL.call(ble_evt);
        }
        raw::BLE_GAP_EVTS_BLE_GAP_EVT_PHY_UPDATE_REQUEST => {
            let peer_preferred_phys = gap_evt.params.phy_update_request.peer_preferred_phys;
            let conn_handle = gap_evt.conn_handle;

            trace!(
                "on_phy_update_request conn_handle={:?} rx_phys={:?} tx_phys={:?}",
                conn_handle,
                peer_preferred_phys.rx_phys,
                peer_preferred_phys.tx_phys
            );

            PHY_UPDATE_REQUEST_CONN.store(conn_handle, Ordering::Relaxed);
            PHY_UPDATE_REQUEST_RX.store(peer_preferred_phys.rx_phys, Ordering::Relaxed);
            PHY_UPDATE_REQUEST_TX.store(peer_preferred_phys.tx_phys, Ordering::Relaxed);
            PHY_UPDATE_REQUEST_PENDING.store(true, Ordering::Relaxed);

            let phys = raw::ble_gap_phys_t {
                rx_phys: peer_preferred_phys.rx_phys,
                tx_phys: peer_preferred_phys.tx_phys,
            };

            let ret = raw::sd_ble_gap_phy_update(conn_handle, &phys as *const raw::ble_gap_phys_t);

            if let Err(_err) = RawError::convert(ret) {
                warn!("sd_ble_gap_phy_update err {:?}", _err);
            }
        }
        raw::BLE_GAP_EVTS_BLE_GAP_EVT_PHY_UPDATE => {
            let phy_update = gap_evt.params.phy_update;

            trace!(
                "on_phy_update conn_handle={:?} status={:?} rx_phy={:?} tx_phy={:?}",
                gap_evt.conn_handle,
                phy_update.status,
                phy_update.rx_phy,
                phy_update.tx_phy
            );

            PHY_UPDATE_CONN.store(gap_evt.conn_handle, Ordering::Relaxed);
            PHY_UPDATE_STATUS.store(phy_update.status, Ordering::Relaxed);
            PHY_UPDATE_RX.store(phy_update.rx_phy, Ordering::Relaxed);
            PHY_UPDATE_TX.store(phy_update.tx_phy, Ordering::Relaxed);
            PHY_UPDATE_PENDING.store(true, Ordering::Relaxed);
        }
        #[cfg(any(feature = "s113", feature = "s132", feature = "s140"))]
        raw::BLE_GAP_EVTS_BLE_GAP_EVT_DATA_LENGTH_UPDATE_REQUEST => {
            let peer_params = gap_evt.params.data_length_update_request.peer_params;

            trace!(
                "on_data_length_update_request conn_handle={:?} max_rx_octets={:?} max_rx_time_us={:?} max_tx_octets={:?} max_tx_time_us={:?}",
                gap_evt.conn_handle,
                peer_params.max_rx_octets,
                peer_params.max_rx_time_us,
                peer_params.max_tx_octets,
                peer_params.max_tx_time_us,
            );

            DLE_REQUEST_CONN.store(gap_evt.conn_handle, Ordering::Relaxed);
            DLE_REQUEST_TX_OCTETS.store(peer_params.max_tx_octets, Ordering::Relaxed);
            DLE_REQUEST_RX_OCTETS.store(peer_params.max_rx_octets, Ordering::Relaxed);
            DLE_REQUEST_TX_TIME_US.store(peer_params.max_tx_time_us, Ordering::Relaxed);
            DLE_REQUEST_RX_TIME_US.store(peer_params.max_rx_time_us, Ordering::Relaxed);
            DLE_REQUEST_PENDING.store(true, Ordering::Relaxed);

            let conn_handle = gap_evt.conn_handle;
            if let Some(mut conn) = Connection::from_handle(conn_handle) {
                let _ = conn.data_length_update(None);
            }
        }
        #[cfg(any(feature = "s113", feature = "s132", feature = "s140"))]
        raw::BLE_GAP_EVTS_BLE_GAP_EVT_DATA_LENGTH_UPDATE => {
            let effective_params = gap_evt.params.data_length_update.effective_params;

            connection::with_state_by_conn_handle(gap_evt.conn_handle, |state| {
                state.data_length_effective = effective_params.max_tx_octets as u8;
            });

            DLE_UPDATE_CONN.store(gap_evt.conn_handle, Ordering::Relaxed);
            DLE_UPDATE_TX_OCTETS.store(effective_params.max_tx_octets, Ordering::Relaxed);
            DLE_UPDATE_RX_OCTETS.store(effective_params.max_rx_octets, Ordering::Relaxed);
            DLE_UPDATE_TX_TIME_US.store(effective_params.max_tx_time_us, Ordering::Relaxed);
            DLE_UPDATE_RX_TIME_US.store(effective_params.max_rx_time_us, Ordering::Relaxed);
            DLE_UPDATE_PENDING.store(true, Ordering::Relaxed);

            debug!(
                "on_data_length_update conn_handle={:?} max_rx_octets={:?} max_rx_time_us={:?} max_tx_octets={:?} max_tx_time_us={:?}",
                gap_evt.conn_handle,
                effective_params.max_rx_octets,
                effective_params.max_rx_time_us,
                effective_params.max_tx_octets,
                effective_params.max_tx_time_us,
            );
        }
        #[cfg(feature = "ble-rssi")]
        raw::BLE_GAP_EVTS_BLE_GAP_EVT_RSSI_CHANGED => {
            let new_rssi = gap_evt.params.rssi_changed.rssi;
            connection::with_state_by_conn_handle(gap_evt.conn_handle, |state| {
                state.rssi = match state.rssi {
                    None => Some(new_rssi),
                    Some(old_rssi) => Some((((old_rssi as i16) * 7 + (new_rssi as i16)) / 8) as i8),
                };
            });
        }
        raw::BLE_GAP_EVTS_BLE_GAP_EVT_SEC_PARAMS_REQUEST => {
            let params = &gap_evt.params.sec_params_request;
            let peer_params = params.peer_params;
            trace!("ble evt sec params request conn={:x}, bond={:?}, io_caps={:?}, keypress={:?}, lesc={:?}, mitm={:?}, oob={:?}, key_size={}..={}",
                    gap_evt.conn_handle, peer_params.bond(), peer_params.io_caps(), peer_params.keypress(), peer_params.lesc(), peer_params.mitm(), peer_params.oob(),
                    peer_params.min_key_size, peer_params.max_key_size);

            if let Some(conn) = Connection::from_handle(gap_evt.conn_handle) {
                let peer_lesc = peer_params.lesc() != 0;
                let (sec_params, is_central, mut keyset) = conn.with_state(|state| {
                    #[cfg(not(feature = "ble-peripheral"))]
                    let sec_params = None;
                    #[cfg(feature = "ble-peripheral")]
                    let sec_params = if state.role == Role::Peripheral {
                        #[cfg(not(feature = "ble-sec"))]
                        let sec_params = default_security_params();
                        #[cfg(feature = "ble-sec")]
                        let sec_params = state
                            .security
                            .handler
                            .map(|h| h.security_params(&conn))
                            .unwrap_or_else(default_security_params);

                        // Enable LESC in peripheral reply when we have a DHKey handler registered.
                        let mut sec_params = sec_params;
                        if unsafe { (*&raw const LESC_DHKEY_FN).is_some() } {
                            sec_params.set_lesc(1);
                        }
                        Some(sec_params)
                    } else {
                        None
                    };

                    // Same pattern as sec_params above: state.role == Role::Central is
                    // unconditionally false whenever Role::Central doesn't exist, but
                    // the variant itself is cfg-gated at its definition, so the
                    // comparison won't even compile without ble-central.
                    #[cfg(not(feature = "ble-central"))]
                    let is_central = false;
                    #[cfg(feature = "ble-central")]
                    let is_central = state.role == Role::Central;

                    (sec_params, is_central, state.keyset(peer_lesc))
                });

                // In central role, sd_ble_gap_authenticate already supplied sec_params.
                let sec_params_ptr = if is_central {
                    core::ptr::null()
                } else {
                    sec_params.as_ref().map(|x| x as *const _).unwrap_or(core::ptr::null())
                };

                // For LESC: keys_own.p_pk must point to our own public key (stable RAM).
                if peer_lesc {
                    keyset.keys_own.p_pk = &raw mut LESC_OWN_PK_BUF;
                }

                let ret = raw::sd_ble_gap_sec_params_reply(
                    gap_evt.conn_handle,
                    raw::BLE_GAP_SEC_STATUS_SUCCESS as u8,
                    sec_params_ptr,
                    &keyset,
                );

                if let Err(_err) = RawError::convert(ret) {
                    warn!("sd_ble_gap_sec_params_reply err {:?}", _err);
                }
            } else {
                warn!("Received SEC_PARAMS_REQUEST with an invalid connection handle");
            }
        }
        raw::BLE_GAP_EVTS_BLE_GAP_EVT_PASSKEY_DISPLAY => {
            let params = &gap_evt.params.passkey_display;
            debug_assert_eq!(params.match_request(), 0);
            trace!(
                "on_passkey_display passkey={}",
                core::str::from_utf8_unchecked(&params.passkey)
            );
            #[cfg(feature = "ble-sec")]
            connection::with_state_by_conn_handle(gap_evt.conn_handle, |state| {
                if let Some(handler) = state.security.handler {
                    handler.display_passkey(&params.passkey)
                }
            });
        }
        raw::BLE_GAP_EVTS_BLE_GAP_EVT_AUTH_KEY_REQUEST => {
            let params = &gap_evt.params.auth_key_request;
            trace!("on_auth_key_request key_type={}", params.key_type);

            #[cfg(not(feature = "ble-sec"))]
            let handled = false;
            #[cfg(feature = "ble-sec")]
            let handled = connection::with_state_by_conn_handle(gap_evt.conn_handle, |state| {
                state
                    .security
                    .handler
                    .and_then(|handler| match u32::from(params.key_type) {
                        raw::BLE_GAP_AUTH_KEY_TYPE_PASSKEY => Connection::from_handle(gap_evt.conn_handle)
                            .map(|conn| handler.enter_passkey(PasskeyReply::new(conn))),
                        raw::BLE_GAP_AUTH_KEY_TYPE_OOB => Connection::from_handle(gap_evt.conn_handle)
                            .map(|conn| handler.recv_out_of_band(OutOfBandReply::new(conn))),
                        _ => None,
                    })
            })
            .is_some();

            if !handled {
                let ret = raw::sd_ble_gap_auth_key_reply(
                    gap_evt.conn_handle,
                    raw::BLE_GAP_AUTH_KEY_TYPE_NONE as u8,
                    core::ptr::null(),
                );

                if let Err(_err) = RawError::convert(ret) {
                    warn!("sd_ble_gap_auth_key_reply err {:?}", _err);
                }
            }
        }
        #[cfg(feature = "ble-peripheral")]
        raw::BLE_GAP_EVTS_BLE_GAP_EVT_SEC_INFO_REQUEST => {
            let params = &gap_evt.params.sec_info_request;
            trace!("ble evt sec info request: enc_info={}, id_info={}, sign_info={}, master_id: {{ ediv: {:x}, rand: {:?} }}, peer_addr: {{ addr: {:?}, addr_id_peer: {}, addr_type: {} }}",
                params.enc_info(), params.id_info(), params.sign_info(), params.master_id.ediv, params.master_id.rand,
                params.peer_addr.addr, params.peer_addr.addr_id_peer(), params.peer_addr.addr_type());

            #[cfg(feature = "ble-sec")]
            let key = Connection::from_handle(gap_evt.conn_handle).and_then(|conn| {
                conn.security_handler()
                    .and_then(|x| x.get_key(&conn, MasterId::from_raw(params.master_id)))
            });

            #[cfg(not(feature = "ble-sec"))]
            let key_ptr = core::ptr::null();
            #[cfg(feature = "ble-sec")]
            let key_ptr = key
                .as_ref()
                .map(|x| x.as_raw() as *const _)
                .unwrap_or(core::ptr::null());

            let ret =
                raw::sd_ble_gap_sec_info_reply(gap_evt.conn_handle, key_ptr, core::ptr::null(), core::ptr::null());

            if let Err(_err) = RawError::convert(ret) {
                warn!("sd_ble_gap_sec_info_reply err {:?}", _err);
            }
        }
        raw::BLE_GAP_EVTS_BLE_GAP_EVT_CONN_SEC_UPDATE => {
            let params = &gap_evt.params.conn_sec_update;
            trace!(
                "ble evt conn sec update sec_mode=({},{}), encr_key_size={}",
                params.conn_sec.sec_mode.sm(),
                params.conn_sec.sec_mode.lv(),
                params.conn_sec.encr_key_size
            );
            if let Some(conn) = Connection::from_handle(gap_evt.conn_handle) {
                conn.with_state(|state| {
                    state.security_mode = SecurityMode::try_from_raw(params.conn_sec.sec_mode).unwrap_or_default();
                    #[cfg(feature = "ble-sec")]
                    if let Some(handler) = state.security.handler {
                        handler.on_security_update(&conn, state.security_mode);
                    }
                });
            }
        }
        raw::BLE_GAP_EVTS_BLE_GAP_EVT_AUTH_STATUS => {
            let params = &gap_evt.params.auth_status;
            trace!(
                "ble evt auth status: bonded={}, error_src={}, lesc={}, kdist_own={}, kdist_peer={}",
                params.bonded(),
                params.error_src(),
                params.lesc(),
                params.kdist_own._bitfield_1.get(0, 8),
                params.kdist_peer._bitfield_1.get(0, 8)
            );
            #[cfg(feature = "ble-sec")]
            if u32::from(params.auth_status) == raw::BLE_GAP_SEC_STATUS_SUCCESS && params.bonded() != 0 {
                if let Some(conn) = Connection::from_handle(gap_evt.conn_handle) {
                    conn.with_state(|state| {
                        if let Some(handler) = state.security.handler {
                            let peer_id = if params.kdist_peer.id() != 0 {
                                IdentityKey::from_raw(state.security.peer_id)
                            } else {
                                debug!("Peer identity key not distributed; falling back to address");
                                IdentityKey::from_addr(state.peer_address)
                            };

                            // Under legacy pairing the LTK is generated by one side and
                            // distributed to the other via SMP key distribution, so the
                            // central reads the copy the peripheral sent it
                            // (peer_enc_key) and the peripheral reads the copy it kept
                            // (own_enc_key). Under LESC there is no such distribution:
                            // both sides derive the *same* symmetric LTK locally from the
                            // ECDH exchange, and each writes its own copy into
                            // own_enc_key (that is what `keyset()` points `keys_own` at,
                            // regardless of role). A central that keeps reading
                            // peer_enc_key for a LESC bond gets an empty key -- nothing
                            // was ever distributed to put there -- while the real LTK
                            // sits unread in own_enc_key.
                            let enc_key = match state.role {
                                // Inlined rather than bound above: a `ble-peripheral`-only
                                // build compiles this arm out entirely, and a separate
                                // `let lesc = ...` would then sit unused with warnings
                                // denied as errors.
                                #[cfg(feature = "ble-central")]
                                Role::Central if params.lesc() != 0 => &state.security.own_enc_key,
                                #[cfg(feature = "ble-central")]
                                Role::Central => &state.security.peer_enc_key,
                                #[cfg(feature = "ble-peripheral")]
                                Role::Peripheral => &state.security.own_enc_key,
                            };

                            handler.on_bonded(
                                &conn,
                                MasterId::from_raw(enc_key.master_id),
                                EncryptionInfo::from_raw(enc_key.enc_info),
                                peer_id,
                            );
                        }
                    });
                }
            }
        }
        #[cfg(feature = "ble-central")]
        raw::BLE_GAP_EVTS_BLE_GAP_EVT_SEC_REQUEST => {
            let params = &gap_evt.params.sec_request;
            trace!(
                "ble evt auth status: bond={}, mitm={}, lesc={}, keypress={}",
                params.bond(),
                params.mitm(),
                params.lesc(),
                params.keypress(),
            );
            if let Some(conn) = Connection::from_handle(gap_evt.conn_handle) {
                #[cfg(feature = "ble-sec")]
                let res = match conn.encrypt() {
                    Ok(()) => Ok(()),
                    Err(EncryptError::NoSecurityHandler) | Err(EncryptError::PeerKeysNotFound) => {
                        conn.request_pairing()
                    }
                    Err(EncryptError::Disconnected) => Err(AuthenticateError::Disconnected),
                    Err(EncryptError::Raw(err)) => Err(AuthenticateError::Raw(err)),
                };
                #[cfg(not(feature = "ble-sec"))]
                let res = conn.request_pairing();
                if let Err(err) = res {
                    warn!("Failed to initiate encryption {:?}", err);
                }
            }
        }
        raw::BLE_GAP_EVTS_BLE_GAP_EVT_LESC_DHKEY_REQUEST => {
            let params = &gap_evt.params.lesc_dhkey_request;
            if let Some(dhkey_fn) = unsafe { LESC_DHKEY_FN } {
                let peer_pk = &(*params.p_pk_peer).pk;
                match dhkey_fn(peer_pk) {
                    Some(key) => {
                        let dhkey = raw::ble_gap_lesc_dhkey_t { key };
                        raw::sd_ble_gap_lesc_dhkey_reply(gap_evt.conn_handle, &dhkey);
                    }
                    None => {
                        warn!("LESC DHKey computation failed; aborting pairing");
                        raw::sd_ble_gap_disconnect(
                            gap_evt.conn_handle,
                            raw::BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION as u8,
                        );
                    }
                }
            } else {
                warn!("LESC_DHKEY_REQUEST with no handler registered");
            }
        }
        // BLE_GAP_EVTS_BLE_GAP_EVT_KEY_PRESSED (LESC central pairing)
        // BLE_GAP_EVTS_BLE_GAP_EVT_RSSI_CHANGED
        // BLE_GAP_EVTS_BLE_GAP_EVT_SCAN_REQ_REPORT
        // BLE_GAP_EVTS_BLE_GAP_EVT_QOS_CHANNEL_SURVEY_REPORT
        _ => {}
    }
}

pub fn set_device_identities_list(
    sd: &Softdevice,
    id_keys: &[IdentityKey],
    local_irks: Option<&[IdentityResolutionKey]>,
) -> Result<(), RawError> {
    let _ = sd;
    const MAX_LEN: usize = raw::BLE_GAP_DEVICE_IDENTITIES_MAX_COUNT as usize;
    assert!(id_keys.len() <= MAX_LEN);
    assert!(local_irks.map(|x| x.len() == id_keys.len()).unwrap_or(true));

    let mut p_id_keys: [*const raw::ble_gap_id_key_t; MAX_LEN] = [core::ptr::null(); MAX_LEN];
    let pp_id_keys = if !id_keys.is_empty() {
        for (a, b) in id_keys.iter().zip(p_id_keys.iter_mut()) {
            *b = a.as_raw() as *const _;
        }
        Some(&p_id_keys[..id_keys.len()])
    } else {
        None
    };

    let mut p_local_irks: [*const raw::ble_gap_irk_t; MAX_LEN] = [core::ptr::null(); MAX_LEN];
    let pp_local_irks = if let Some(local_irks) = local_irks {
        for (a, b) in local_irks.iter().zip(p_local_irks.iter_mut()) {
            *b = a.as_raw() as *const _;
        }
        Some(&p_local_irks[..local_irks.len()])
    } else {
        None
    };

    let ret = unsafe {
        raw::sd_ble_gap_device_identities_set(
            pp_id_keys.map(|x| x.as_ptr()).unwrap_or(core::ptr::null()),
            pp_local_irks.map(|x| x.as_ptr()).unwrap_or(core::ptr::null()),
            id_keys.len() as u8,
        )
    };
    RawError::convert(ret)
}

pub fn set_whitelist(sd: &Softdevice, addrs: &[Address]) -> Result<(), RawError> {
    let _ = sd;
    const MAX_LEN: usize = raw::BLE_GAP_WHITELIST_ADDR_MAX_COUNT as usize;
    assert!(addrs.len() <= MAX_LEN);

    let mut p_addrs: [*const raw::ble_gap_addr_t; MAX_LEN] = [core::ptr::null(); MAX_LEN];
    let pp_addrs = if !addrs.is_empty() {
        for (a, b) in addrs.iter().zip(p_addrs.iter_mut()) {
            *b = a.as_raw() as *const _;
        }
        Some(&p_addrs[..addrs.len()])
    } else {
        None
    };

    let ret = unsafe {
        raw::sd_ble_gap_whitelist_set(
            pp_addrs.map(|x| x.as_ptr()).unwrap_or(core::ptr::null()),
            addrs.len() as u8,
        )
    };
    RawError::convert(ret)
}

pub fn default_security_params() -> raw::ble_gap_sec_params_t {
    let mut sec_params: raw::ble_gap_sec_params_t = unsafe { core::mem::zeroed() };

    sec_params.min_key_size = 7;
    sec_params.max_key_size = 16;

    sec_params.set_io_caps(raw::BLE_GAP_IO_CAPS_NONE as u8);
    sec_params
}

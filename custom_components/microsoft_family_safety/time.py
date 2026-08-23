"""Screen-time interval entities."""
from datetime import time as dt_time

from homeassistant.components.time import TimeEntity
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, DAYS


def _parse_time(value):
    if not isinstance(value, str):
        return None
    try:
        parts = value.split(":")
        hour = int(parts[0])
        minute = int(parts[1]) if len(parts) > 1 else 0
        # Microsoft can represent the end of a day as 24:00:00; HA's time
        # entity cannot, so expose the last representable minute instead.
        if hour >= 24:
            return dt_time(23, 59)
        return dt_time(hour, minute)
    except (TypeError, ValueError, IndexError):
        return None


def day_times(policy, key):
    """Return the visible start/end interval for a weekday policy.

    Older code expected a 48-slot boolean timeline.  The current Microsoft web
    API returns ``allowedIntervals`` as objects such as
    ``{"begin":"06:00:00","end":"22:00:00"}``.  Support both formats.
    If Microsoft returns multiple disjoint intervals, the entities expose the
    first begin and last end; the raw intervals remain available in the policy
    sensor attributes.
    """
    daily = (policy or {}).get("dailyRestrictions") or (policy or {}).get("DailyRestrictions") or {}
    d = daily.get(key) or daily.get(key.capitalize()) or {}
    vals = d.get("timeline") or d.get("allowedIntervals") or d.get("AllowedIntervals")

    if isinstance(vals, list) and len(vals) == 48 and all(isinstance(x, bool) for x in vals):
        ids = [i for i, enabled in enumerate(vals) if enabled]
        if ids:
            sm = ids[0] * 30
            em = (ids[-1] + 1) * 30
            return (
                dt_time(sm // 60, sm % 60),
                dt_time(23, 59) if em >= 1440 else dt_time(em // 60, em % 60),
            )

    if isinstance(vals, list):
        ranges = []
        for interval in vals:
            if not isinstance(interval, dict):
                continue
            # The live /family/api/st response includes beginTimeSpan and
            # endTimeSpan alongside ISO-8601 begin/end values. Prefer the
            # conventional time-span fields because they map directly to HA.
            begin = _parse_time(
                interval.get("beginTimeSpan")
                or interval.get("BeginTimeSpan")
                or interval.get("begin")
                or interval.get("Begin")
                or interval.get("start")
                or interval.get("Start")
            )
            end = _parse_time(
                interval.get("endTimeSpan")
                or interval.get("EndTimeSpan")
                or interval.get("end")
                or interval.get("End")
            )
            if begin is not None and end is not None:
                ranges.append((begin, end))
        if ranges:
            return ranges[0][0], ranges[-1][1]

    return None, None


async def async_setup_entry(hass, entry, async_add_entities):
    c = hass.data[DOMAIN][entry.entry_id]
    known = set()

    def add():
        entities = []
        for aid in (c.data or {}).get("accounts", {}):
            if aid in known:
                continue
            known.add(aid)
            for idx, key, label in DAYS:
                entities += [
                    Interval(c, entry, aid, idx, key, label, True),
                    Interval(c, entry, aid, idx, key, label, False),
                ]
        if entities:
            async_add_entities(entities)

    add()
    entry.async_on_unload(c.async_add_listener(add))


class Interval(CoordinatorEntity, TimeEntity):
    def __init__(self, c, e, aid, idx, key, label, start):
        super().__init__(c)
        self.aid = aid
        self.idx = idx
        self.key = key
        self.start = start
        name = ((c.data or {}).get("accounts", {}).get(aid) or {}).get("first_name", "Unknown")
        kind = "Start" if start else "End"
        self._attr_unique_id = f"{e.entry_id}_{aid}_interval_{key}_{kind.lower()}"
        self._attr_name = f"{name} {label} {kind}"
        # Attach the time entities to the same Family Safety child device as
        # the number/switch entities. Without DeviceInfo Home Assistant keeps
        # them as orphaned standalone entities, so they do not appear on the
        # child device page even though their states are valid.
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self.aid)},
            name=f"{name} (Family Safety)",
            manufacturer="Microsoft",
            model="Family Safety Account",
        )

    @property
    def native_value(self):
        policy = ((self.coordinator.data or {}).get("accounts", {}).get(self.aid) or {}).get("screentime_policy")
        start, end = day_times(policy, self.key)
        return start if self.start else end

    @property
    def extra_state_attributes(self):
        """Expose the parsed pair and raw Microsoft interval for diagnostics."""
        policy = ((self.coordinator.data or {}).get("accounts", {}).get(self.aid) or {}).get("screentime_policy") or {}
        start, end = day_times(policy, self.key)
        daily = policy.get("dailyRestrictions") or policy.get("DailyRestrictions") or {}
        day = daily.get(self.key) or daily.get(self.key.capitalize()) or {}
        return {
            "user_id": self.aid,
            "day": self.key,
            "parsed_start": start.isoformat() if start else None,
            "parsed_end": end.isoformat() if end else None,
            "allowed_intervals": day.get("allowedIntervals", day.get("AllowedIntervals")),
            "allowance": day.get("allowance", day.get("Allowance")),
        }

    async def async_set_value(self, value):
        policy = ((self.coordinator.data or {}).get("accounts", {}).get(self.aid) or {}).get("screentime_policy")
        start, end = day_times(policy, self.key)
        if self.start:
            start = value
            end = end or dt_time(22)
        else:
            start = start or dt_time(7)
            end = value
        await self.coordinator.async_set_screentime_intervals(
            self.aid, self.idx, start.hour, start.minute, end.hour, end.minute
        )

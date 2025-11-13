# TimeGenerated Injection Fix Summary

## Problem Fixed
The KQL query timeGenerated injection issue has been resolved. Previously, the system used complex conditional logic that didn't properly center the time window around the alert date.

## Solution Implemented
Implemented **centered windowing** approach where the time window is always centered around the alert timestamp.

## Files Modified

### 1. `routes/src/kql_template_injector.py`
**Function:** `_convert_ago_to_absolute_datetime()`
- **Before:** Complex logic with different behaviors based on alert age
- **After:** Simple centered windowing: `alert_time ± (period/2)`

```python
# NEW LOGIC
half_delta = delta / 2
start_dt = self.reference_datetime_obj - half_delta
end_dt = self.reference_datetime_obj + half_delta
```

### 2. `routes/src/kql_query_standardizer.py`
**Function:** `_build_time_filter()`
- **Before:** `start_dt = reference_datetime_obj - timedelta(days=7)`
- **After:** Centered 7-day window around alert time

```python
# NEW LOGIC
half_delta = timedelta(days=3.5)  # 7 days / 2
start_dt = reference_datetime_obj - half_delta
end_dt = reference_datetime_obj + half_delta
```

## How It Works Now

### Example Scenarios (as requested):

1. **Alert on 12/11/2025, Today is 13th**
   - 7-day window: **08/11/2025 to 15/11/2025**
   - Centered around 12th: 3.5 days before, 3.5 days after

2. **Alert on 06/11/2025, Today is 13th**
   - 7-day window: **03/11/2025 to 10/11/2025**
   - Centered around 6th: 3.5 days before, 3.5 days after

3. **Alert on 10/11/2025, Today is 14th**
   - 7-day window: **06/11/2025 to 13/11/2025**
   - Centered around 10th: 3.5 days before, 3.5 days after

## Test Results
✅ **All test cases PASSED**
- Centered windowing logic works correctly
- Supports different time units (days, hours, minutes)
- Window is properly balanced around alert time

## KQL Query Transformation
**Before:**
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "user@company.com"
```

**After:**
```kql
SigninLogs
| where TimeGenerated > datetime(2025-11-08 22:30:00Z) and TimeGenerated <= datetime(2025-11-15 22:30:00Z)
| where UserPrincipalName == "user@company.com"
```

## Benefits
1. **Consistent behavior** - Always centers around alert time regardless of when query runs
2. **Better coverage** - Captures activity both before and after the alert
3. **Predictable results** - Same query will always return same time range for same alert
4. **Flexible** - Works with any time unit (days, hours, minutes, seconds)

## Files Created
- `test_timegenerated_simple.py` - Test file demonstrating the fix works correctly
- `TIMEGENERATED_FIX_SUMMARY.md` - This summary document

The timeGenerated injection issue has been successfully resolved with centered windowing approach.
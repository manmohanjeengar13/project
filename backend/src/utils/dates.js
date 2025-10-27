/**
 * Date Utilities - MILITARY-GRADE Date/Time Functions
 * Enterprise-level date manipulation and calculation utilities
 * 
 * @module utils/dates
 * @version 3.0.0
 * @license MIT
 * 
 * ============================================================================
 * FEATURES:
 * ============================================================================
 * - Date parsing and validation
 * - Date arithmetic (add, subtract)
 * - Date comparison
 * - Date range operations
 * - Timezone conversions
 * - Business day calculations
 * - Age calculations
 * - Duration calculations
 * - Calendar utilities
 * - Holiday detection
 * - Week/month/year utilities
 * - ISO 8601 support
 * - Unix timestamp operations
 * 
 * @author Security Engineering Team
 * @copyright 2024 SQLi Demo Platform
 */

import {
  addDays,
  addMonths,
  addYears,
  subDays,
  subMonths,
  subYears,
  startOfDay,
  endOfDay,
  startOfWeek,
  endOfWeek,
  startOfMonth,
  endOfMonth,
  startOfYear,
  endOfYear,
  differenceInDays,
  differenceInMonths,
  differenceInYears,
  differenceInHours,
  differenceInMinutes,
  differenceInSeconds,
  isAfter,
  isBefore,
  isEqual,
  isSameDay,
  isSameMonth,
  isSameYear,
  isWeekend,
  isWithinInterval,
  parseISO,
  formatISO,
  getDay,
  getDaysInMonth,
  getWeek,
  setDay,
  setMonth,
  setYear
} from 'date-fns';

// ============================================================================
// DATE CREATION
// ============================================================================

/**
 * Get current date
 * @returns {Date} Current date
 */
export const now = () => {
  return new Date();
};

/**
 * Get today at midnight
 * @returns {Date} Today at 00:00:00
 */
export const today = () => {
  return startOfDay(new Date());
};

/**
 * Get yesterday
 * @returns {Date} Yesterday
 */
export const yesterday = () => {
  return subDays(today(), 1);
};

/**
 * Get tomorrow
 * @returns {Date} Tomorrow
 */
export const tomorrow = () => {
  return addDays(today(), 1);
};

/**
 * Parse date string
 * @param {string} dateStr - Date string (ISO 8601)
 * @returns {Date} Parsed date
 */
export const parseDate = (dateStr) => {
  return parseISO(dateStr);
};

/**
 * Create date from parts
 * @param {number} year - Year
 * @param {number} month - Month (1-12)
 * @param {number} day - Day
 * @returns {Date} Created date
 */
export const createDate = (year, month, day) => {
  return new Date(year, month - 1, day);
};

// ============================================================================
// DATE ARITHMETIC
// ============================================================================

/**
 * Add days to date
 * @param {Date} date - Base date
 * @param {number} days - Days to add
 * @returns {Date} New date
 */
export const addDaysToDate = (date, days) => {
  return addDays(date, days);
};

/**
 * Subtract days from date
 * @param {Date} date - Base date
 * @param {number} days - Days to subtract
 * @returns {Date} New date
 */
export const subtractDays = (date, days) => {
  return subDays(date, days);
};

/**
 * Add months to date
 * @param {Date} date - Base date
 * @param {number} months - Months to add
 * @returns {Date} New date
 */
export const addMonthsToDate = (date, months) => {
  return addMonths(date, months);
};

/**
 * Subtract months from date
 * @param {Date} date - Base date
 * @param {number} months - Months to subtract
 * @returns {Date} New date
 */
export const subtractMonths = (date, months) => {
  return subMonths(date, months);
};

/**
 * Add years to date
 * @param {Date} date - Base date
 * @param {number} years - Years to add
 * @returns {Date} New date
 */
export const addYearsToDate = (date, years) => {
  return addYears(date, years);
};

/**
 * Subtract years from date
 * @param {Date} date - Base date
 * @param {number} years - Years to subtract
 * @returns {Date} New date
 */
export const subtractYears = (date, years) => {
  return subYears(date, years);
};

// ============================================================================
// DATE COMPARISON
// ============================================================================

/**
 * Check if date is after another
 * @param {Date} date - Date to check
 * @param {Date} dateToCompare - Date to compare against
 * @returns {boolean} Is after
 */
export const isDateAfter = (date, dateToCompare) => {
  return isAfter(date, dateToCompare);
};

/**
 * Check if date is before another
 * @param {Date} date - Date to check
 * @param {Date} dateToCompare - Date to compare against
 * @returns {boolean} Is before
 */
export const isDateBefore = (date, dateToCompare) => {
  return isBefore(date, dateToCompare);
};

/**
 * Check if dates are equal
 * @param {Date} date1 - First date
 * @param {Date} date2 - Second date
 * @returns {boolean} Are equal
 */
export const areDatesEqual = (date1, date2) => {
  return isEqual(date1, date2);
};

/**
 * Check if dates are same day
 * @param {Date} date1 - First date
 * @param {Date} date2 - Second date
 * @returns {boolean} Same day
 */
export const isSameDayAs = (date1, date2) => {
  return isSameDay(date1, date2);
};

/**
 * Check if dates are in same month
 * @param {Date} date1 - First date
 * @param {Date} date2 - Second date
 * @returns {boolean} Same month
 */
export const isSameMonthAs = (date1, date2) => {
  return isSameMonth(date1, date2);
};

/**
 * Check if dates are in same year
 * @param {Date} date1 - First date
 * @param {Date} date2 - Second date
 * @returns {boolean} Same year
 */
export const isSameYearAs = (date1, date2) => {
  return isSameYear(date1, date2);
};

// ============================================================================
// DATE RANGES
// ============================================================================

/**
 * Check if date is within range
 * @param {Date} date - Date to check
 * @param {Date} start - Range start
 * @param {Date} end - Range end
 * @returns {boolean} Is within range
 */
export const isDateInRange = (date, start, end) => {
  return isWithinInterval(date, { start, end });
};

/**
 * Get start of day
 * @param {Date} date - Date
 * @returns {Date} Start of day
 */
export const getStartOfDay = (date) => {
  return startOfDay(date);
};

/**
 * Get end of day
 * @param {Date} date - Date
 * @returns {Date} End of day
 */
export const getEndOfDay = (date) => {
  return endOfDay(date);
};

/**
 * Get start of week
 * @param {Date} date - Date
 * @returns {Date} Start of week
 */
export const getStartOfWeek = (date) => {
  return startOfWeek(date);
};

/**
 * Get end of week
 * @param {Date} date - Date
 * @returns {Date} End of week
 */
export const getEndOfWeek = (date) => {
  return endOfWeek(date);
};

/**
 * Get start of month
 * @param {Date} date - Date
 * @returns {Date} Start of month
 */
export const getStartOfMonth = (date) => {
  return startOfMonth(date);
};

/**
 * Get end of month
 * @param {Date} date - Date
 * @returns {Date} End of month
 */
export const getEndOfMonth = (date) => {
  return endOfMonth(date);
};

/**
 * Get start of year
 * @param {Date} date - Date
 * @returns {Date} Start of year
 */
export const getStartOfYear = (date) => {
  return startOfYear(date);
};

/**
 * Get end of year
 * @param {Date} date - Date
 * @returns {Date} End of year
 */
export const getEndOfYear = (date) => {
  return endOfYear(date);
};

// ============================================================================
// DATE DIFFERENCES
// ============================================================================

/**
 * Get difference in days
 * @param {Date} date1 - First date
 * @param {Date} date2 - Second date
 * @returns {number} Days difference
 */
export const daysBetween = (date1, date2) => {
  return Math.abs(differenceInDays(date1, date2));
};

/**
 * Get difference in months
 * @param {Date} date1 - First date
 * @param {Date} date2 - Second date
 * @returns {number} Months difference
 */
export const monthsBetween = (date1, date2) => {
  return Math.abs(differenceInMonths(date1, date2));
};

/**
 * Get difference in years
 * @param {Date} date1 - First date
 * @param {Date} date2 - Second date
 * @returns {number} Years difference
 */
export const yearsBetween = (date1, date2) => {
  return Math.abs(differenceInYears(date1, date2));
};

/**
 * Get difference in hours
 * @param {Date} date1 - First date
 * @param {Date} date2 - Second date
 * @returns {number} Hours difference
 */
export const hoursBetween = (date1, date2) => {
  return Math.abs(differenceInHours(date1, date2));
};

/**
 * Get difference in minutes
 * @param {Date} date1 - First date
 * @param {Date} date2 - Second date
 * @returns {number} Minutes difference
 */
export const minutesBetween = (date1, date2) => {
  return Math.abs(differenceInMinutes(date1, date2));
};

/**
 * Get difference in seconds
 * @param {Date} date1 - First date
 * @param {Date} date2 - Second date
 * @returns {number} Seconds difference
 */
export const secondsBetween = (date1, date2) => {
  return Math.abs(differenceInSeconds(date1, date2));
};

// ============================================================================
// AGE CALCULATIONS
// ============================================================================

/**
 * Calculate age from birth date
 * @param {Date} birthDate - Birth date
 * @returns {number} Age in years
 */
export const calculateAge = (birthDate) => {
  return yearsBetween(birthDate, now());
};

/**
 * Calculate age at specific date
 * @param {Date} birthDate - Birth date
 * @param {Date} atDate - Date to calculate age at
 * @returns {number} Age in years
 */
export const calculateAgeAt = (birthDate, atDate) => {
  return yearsBetween(birthDate, atDate);
};

/**
 * Check if person is adult
 * @param {Date} birthDate - Birth date
 * @param {number} adultAge - Adult age threshold
 * @returns {boolean} Is adult
 */
export const isAdult = (birthDate, adultAge = 18) => {
  return calculateAge(birthDate) >= adultAge;
};

// ============================================================================
// BUSINESS DAYS
// ============================================================================

/**
 * Check if date is weekend
 * @param {Date} date - Date
 * @returns {boolean} Is weekend
 */
export const isWeekendDay = (date) => {
  return isWeekend(date);
};

/**
 * Check if date is weekday
 * @param {Date} date - Date
 * @returns {boolean} Is weekday
 */
export const isWeekday = (date) => {
  return !isWeekend(date);
};

/**
 * Add business days
 * @param {Date} date - Start date
 * @param {number} days - Business days to add
 * @returns {Date} Result date
 */
export const addBusinessDays = (date, days) => {
  let result = new Date(date);
  let addedDays = 0;
  
  while (addedDays < days) {
    result = addDays(result, 1);
    if (isWeekday(result)) {
      addedDays++;
    }
  }
  
  return result;
};

/**
 * Count business days between dates
 * @param {Date} startDate - Start date
 * @param {Date} endDate - End date
 * @returns {number} Business days count
 */
export const businessDaysBetween = (startDate, endDate) => {
  let count = 0;
  let current = new Date(startDate);
  
  while (current <= endDate) {
    if (isWeekday(current)) {
      count++;
    }
    current = addDays(current, 1);
  }
  
  return count;
};

// ============================================================================
// CALENDAR UTILITIES
// ============================================================================

/**
 * Get day of week (0 = Sunday)
 * @param {Date} date - Date
 * @returns {number} Day of week
 */
export const getDayOfWeek = (date) => {
  return getDay(date);
};

/**
 * Get days in month
 * @param {Date} date - Date
 * @returns {number} Days in month
 */
export const getDaysInMonthCount = (date) => {
  return getDaysInMonth(date);
};

/**
 * Get week number
 * @param {Date} date - Date
 * @returns {number} Week number
 */
export const getWeekNumber = (date) => {
  return getWeek(date);
};

/**
 * Get month name
 * @param {Date} date - Date
 * @param {string} locale - Locale
 * @returns {string} Month name
 */
export const getMonthName = (date, locale = 'en-US') => {
  return date.toLocaleDateString(locale, { month: 'long' });
};

/**
 * Get day name
 * @param {Date} date - Date
 * @param {string} locale - Locale
 * @returns {string} Day name
 */
export const getDayName = (date, locale = 'en-US') => {
  return date.toLocaleDateString(locale, { weekday: 'long' });
};

/**
 * Get quarter
 * @param {Date} date - Date
 * @returns {number} Quarter (1-4)
 */
export const getQuarter = (date) => {
  return Math.floor((date.getMonth() + 3) / 3);
};

/**
 * Is leap year
 * @param {number} year - Year
 * @returns {boolean} Is leap year
 */
export const isLeapYear = (year) => {
  return (year % 4 === 0 && year % 100 !== 0) || (year % 400 === 0);
};

// ============================================================================
// UNIX TIMESTAMP
// ============================================================================

/**
 * Get Unix timestamp (seconds)
 * @param {Date} date - Date
 * @returns {number} Unix timestamp
 */
export const toUnixTimestamp = (date = new Date()) => {
  return Math.floor(date.getTime() / 1000);
};

/**
 * Create date from Unix timestamp
 * @param {number} timestamp - Unix timestamp (seconds)
 * @returns {Date} Date object
 */
export const fromUnixTimestamp = (timestamp) => {
  return new Date(timestamp * 1000);
};

/**
 * Get milliseconds timestamp
 * @param {Date} date - Date
 * @returns {number} Milliseconds timestamp
 */
export const toMilliseconds = (date = new Date()) => {
  return date.getTime();
};

/**
 * Create date from milliseconds
 * @param {number} ms - Milliseconds timestamp
 * @returns {Date} Date object
 */
export const fromMilliseconds = (ms) => {
  return new Date(ms);
};

// ============================================================================
// ISO 8601
// ============================================================================

/**
 * Format date as ISO 8601
 * @param {Date} date - Date
 * @returns {string} ISO string
 */
export const toISOString = (date = new Date()) => {
  return formatISO(date);
};

/**
 * Parse ISO 8601 string
 * @param {string} isoString - ISO string
 * @returns {Date} Date object
 */
export const fromISOString = (isoString) => {
  return parseISO(isoString);
};

// ============================================================================
// TIMEZONE OPERATIONS
// ============================================================================

/**
 * Get timezone offset in minutes
 * @param {Date} date - Date
 * @returns {number} Offset in minutes
 */
export const getTimezoneOffset = (date = new Date()) => {
  return date.getTimezoneOffset();
};

/**
 * Convert to UTC
 * @param {Date} date - Local date
 * @returns {Date} UTC date
 */
export const toUTC = (date) => {
  return new Date(date.getTime() + date.getTimezoneOffset() * 60000);
};

/**
 * Convert from UTC
 * @param {Date} date - UTC date
 * @returns {Date} Local date
 */
export const fromUTC = (date) => {
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000);
};

/**
 * Get timezone name
 * @param {Date} date - Date
 * @returns {string} Timezone name
 */
export const getTimezoneName = (date = new Date()) => {
  return Intl.DateTimeFormat().resolvedOptions().timeZone;
};

// ============================================================================
// DATE VALIDATION
// ============================================================================

/**
 * Check if date is valid
 * @param {Date} date - Date to check
 * @returns {boolean} Is valid
 */
export const isValidDate = (date) => {
  return date instanceof Date && !isNaN(date.getTime());
};

/**
 * Check if string is valid date
 * @param {string} dateStr - Date string
 * @returns {boolean} Is valid
 */
export const isValidDateString = (dateStr) => {
  const date = new Date(dateStr);
  return isValidDate(date);
};

/**
 * Check if date is in past
 * @param {Date} date - Date
 * @returns {boolean} Is in past
 */
export const isInPast = (date) => {
  return isBefore(date, now());
};

/**
 * Check if date is in future
 * @param {Date} date - Date
 * @returns {boolean} Is in future
 */
export const isInFuture = (date) => {
  return isAfter(date, now());
};

/**
 * Check if date is today
 * @param {Date} date - Date
 * @returns {boolean} Is today
 */
export const isToday = (date) => {
  return isSameDay(date, now());
};

// ============================================================================
// DATE GENERATION
// ============================================================================

/**
 * Generate date range
 * @param {Date} start - Start date
 * @param {Date} end - End date
 * @returns {Array<Date>} Array of dates
 */
export const generateDateRange = (start, end) => {
  const dates = [];
  let current = new Date(start);
  
  while (current <= end) {
    dates.push(new Date(current));
    current = addDays(current, 1);
  }
  
  return dates;
};

/**
 * Generate month dates
 * @param {number} year - Year
 * @param {number} month - Month (1-12)
 * @returns {Array<Date>} Array of dates in month
 */
export const generateMonthDates = (year, month) => {
  const start = createDate(year, month, 1);
  const end = getEndOfMonth(start);
  return generateDateRange(start, end);
};

/**
 * Get last N days
 * @param {number} days - Number of days
 * @returns {Array<Date>} Array of dates
 */
export const getLastNDays = (days) => {
  const end = today();
  const start = subDays(end, days - 1);
  return generateDateRange(start, end);
};

/**
 * Get next N days
 * @param {number} days - Number of days
 * @returns {Array<Date>} Array of dates
 */
export const getNextNDays = (days) => {
  const start = today();
  const end = addDays(start, days - 1);
  return generateDateRange(start, end);
};

// ============================================================================
// DATE ROUNDING
// ============================================================================

/**
 * Round date to nearest hour
 * @param {Date} date - Date
 * @returns {Date} Rounded date
 */
export const roundToNearestHour = (date) => {
  const rounded = new Date(date);
  rounded.setMinutes(rounded.getMinutes() >= 30 ? 60 : 0, 0, 0);
  return rounded;
};

/**
 * Round date to nearest day
 * @param {Date} date - Date
 * @returns {Date} Rounded date
 */
export const roundToNearestDay = (date) => {
  const hours = date.getHours();
  return hours >= 12 ? addDays(startOfDay(date), 1) : startOfDay(date);
};

/**
 * Floor date to hour
 * @param {Date} date - Date
 * @returns {Date} Floored date
 */
export const floorToHour = (date) => {
  const floored = new Date(date);
  floored.setMinutes(0, 0, 0);
  return floored;
};

/**
 * Ceiling date to hour
 * @param {Date} date - Date
 * @returns {Date} Ceiled date
 */
export const ceilToHour = (date) => {
  const ceiled = new Date(date);
  if (ceiled.getMinutes() > 0 || ceiled.getSeconds() > 0 || ceiled.getMilliseconds() > 0) {
    ceiled.setHours(ceiled.getHours() + 1, 0, 0, 0);
  }
  return ceiled;
};

// ============================================================================
// HOLIDAYS (US)
// ============================================================================

/**
 * Get US holidays for a year
 * @param {number} year - Year
 * @returns {object} Holiday dates
 */
export const getUSHolidays = (year) => {
  return {
    newYearsDay: createDate(year, 1, 1),
    independenceDay: createDate(year, 7, 4),
    veteransDay: createDate(year, 11, 11),
    christmas: createDate(year, 12, 25)
  };
};

/**
 * Check if date is US holiday
 * @param {Date} date - Date
 * @returns {boolean} Is holiday
 */
export const isUSHoliday = (date) => {
  const year = date.getFullYear();
  const holidays = Object.values(getUSHolidays(year));
  return holidays.some(holiday => isSameDay(date, holiday));
};

// ============================================================================
// DURATION FORMATTING
// ============================================================================

/**
 * Format duration between dates
 * @param {Date} start - Start date
 * @param {Date} end - End date
 * @returns {object} Duration object
 */
export const getDuration = (start, end) => {
  const diffMs = Math.abs(end - start);
  
  return {
    days: Math.floor(diffMs / (1000 * 60 * 60 * 24)),
    hours: Math.floor(diffMs / (1000 * 60 * 60)) % 24,
    minutes: Math.floor(diffMs / (1000 * 60)) % 60,
    seconds: Math.floor(diffMs / 1000) % 60,
    milliseconds: diffMs % 1000
  };
};

/**
 * Format duration as string
 * @param {Date} start - Start date
 * @param {Date} end - End date
 * @returns {string} Formatted duration
 */
export const formatDuration = (start, end) => {
  const duration = getDuration(start, end);
  const parts = [];
  
  if (duration.days > 0) parts.push(`${duration.days}d`);
  if (duration.hours > 0) parts.push(`${duration.hours}h`);
  if (duration.minutes > 0) parts.push(`${duration.minutes}m`);
  if (duration.seconds > 0) parts.push(`${duration.seconds}s`);
  
  return parts.join(' ') || '0s';
};

// ============================================================================
// DATE MANIPULATION
// ============================================================================

/**
 * Set time on date
 * @param {Date} date - Date
 * @param {number} hours - Hours
 * @param {number} minutes - Minutes
 * @param {number} seconds - Seconds
 * @returns {Date} Date with time set
 */
export const setTime = (date, hours = 0, minutes = 0, seconds = 0) => {
  const result = new Date(date);
  result.setHours(hours, minutes, seconds, 0);
  return result;
};

/**
 * Clone date
 * @param {Date} date - Date to clone
 * @returns {Date} Cloned date
 */
export const cloneDate = (date) => {
  return new Date(date.getTime());
};

/**
 * Get min date from array
 * @param {Array<Date>} dates - Array of dates
 * @returns {Date} Earliest date
 */
export const minDate = (dates) => {
  return new Date(Math.min(...dates.map(d => d.getTime())));
};

/**
 * Get max date from array
 * @param {Array<Date>} dates - Array of dates
 * @returns {Date} Latest date
 */
export const maxDate = (dates) => {
  return new Date(Math.max(...dates.map(d => d.getTime())));
};

/**
 * Sort dates ascending
 * @param {Array<Date>} dates - Array of dates
 * @returns {Array<Date>} Sorted dates
 */
export const sortDatesAsc = (dates) => {
  return [...dates].sort((a, b) => a - b);
};

/**
 * Sort dates descending
 * @param {Array<Date>} dates - Array of dates
 * @returns {Array<Date>} Sorted dates
 */
export const sortDatesDesc = (dates) => {
  return [...dates].sort((a, b) => b - a);
};

// ============================================================================
// EXPORTS
// ============================================================================

export default {
  // Creation
  now,
  today,
  yesterday,
  tomorrow,
  parseDate,
  createDate,
  
  // Arithmetic
  addDaysToDate,
  subtractDays,
  addMonthsToDate,
  subtractMonths,
  addYearsToDate,
  subtractYears,
  
  // Comparison
  isDateAfter,
  isDateBefore,
  areDatesEqual,
  isSameDayAs,
  isSameMonthAs,
  isSameYearAs,
  
  // Ranges
  isDateInRange,
  getStartOfDay,
  getEndOfDay,
  getStartOfWeek,
  getEndOfWeek,
  getStartOfMonth,
  getEndOfMonth,
  getStartOfYear,
  getEndOfYear,
  
  // Differences
  daysBetween,
  monthsBetween,
  yearsBetween,
  hoursBetween,
  minutesBetween,
  secondsBetween,
  
  // Age
  calculateAge,
  calculateAgeAt,
  isAdult,
  
  // Business Days
  isWeekendDay,
  isWeekday,
  addBusinessDays,
  businessDaysBetween,
  
  // Calendar
  getDayOfWeek,
  getDaysInMonthCount,
  getWeekNumber,
  getMonthName,
  getDayName,
  getQuarter,
  isLeapYear,
  
  // Unix
  toUnixTimestamp,
  fromUnixTimestamp,
  toMilliseconds,
  fromMilliseconds,
  
  // ISO
  toISOString,
  fromISOString,
  
  // Timezone
  getTimezoneOffset,
  toUTC,
  fromUTC,
  getTimezoneName,
  
  // Validation
  isValidDate,
  isValidDateString,
  isInPast,
  isInFuture,
  isToday,
  
  // Generation
  generateDateRange,
  generateMonthDates,
  getLastNDays,
  getNextNDays,
  
  // Rounding
  roundToNearestHour,
  roundToNearestDay,
  floorToHour,
  ceilToHour,
  
  // Holidays
  getUSHolidays,
  isUSHoliday,
  
  // Duration
  getDuration,
  formatDuration,
  
  // Manipulation
  setTime,
  cloneDate,
  minDate,
  maxDate,
  sortDatesAsc,
  sortDatesDesc
};

from datetime import datetime, time, timedelta
import holidays

holiday_calendar = holidays.country_holidays(
    "US",
    subdiv="MI"
)
print(holiday_calendar)
print("pyholidays appears to be working!")

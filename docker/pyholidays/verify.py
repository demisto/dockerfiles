from datetime import datetime, time, timedelta
import holidays

holiday_calendar = holidays.country_holidays(
    "US",
    subdiv="MI"
)

print("pyholidays appears to be working!")

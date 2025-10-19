# Web Interface Structure

This directory contains the restructured web interface for the Advanced Network Scanner, organized into a modular Flask application.

## Directory Structure

```
web/
├── app.py                 # Main Flask application
├── routes/                # Route handlers
│   ├── __init__.py        # Package initializer
│   ├── main_routes.py     # Main dashboard routes
│   ├── scan_routes.py     # Network scanning routes
│   ├── camera_routes.py   # Camera detection routes
│   ├── surrounding_routes.py # Surrounding networks routes
│   ├── history_routes.py  # Scan history routes
│   ├── settings_routes.py # Settings routes
│   └── api_routes.py      # API endpoints
├── templates/             # HTML templates
│   ├── base.html          # Base template
│   ├── main.html          # Main dashboard
│   ├── scan.html          # Network scanning page
│   ├── cameras.html       # Camera detection page
│   ├── surrounding.html   # Surrounding networks page
│   ├── history.html       # Scan history page
│   └── settings.html      # Settings page
└── static/                # Static assets
    ├── css/
    │   └── style.css      # Main stylesheet
    └── js/
        └── script.js      # Global JavaScript
```

## Running the Web Interface

To run the web interface, execute the following command from the project root:

```bash
python web/app.py
```

The web interface will be available at http://localhost:8080

## Features

- Modular structure for easier maintenance
- Separation of concerns (routes, templates, static files)
- Responsive design
- Real-time status updates
- API endpoints for AJAX requests
- Template inheritance for consistent layout

## Routes

- `/` - Main dashboard
- `/scan` - Network scanning configuration
- `/cameras` - Camera detection
- `/surrounding` - Surrounding networks detection
- `/history` - Scan history
- `/settings` - Application settings
- `/api/*` - REST API endpoints

## API Endpoints

- `GET /api/status` - Get scan status
- `GET /api/results` - Get vulnerability results
- `GET /api/cameras` - Get camera detection results
- `GET /api/history` - Get scan history
- `POST /api/scan_network` - Start network scan
- `POST /api/update_github` - Update scanner from GitHub
# Neo4j Dashboard

A powerful web-based dashboard for visualizing and managing Neo4j graph databases. This application provides an intuitive interface for exploring, querying, and managing your graph data.

## Features

- **Graph Visualization**: Interactive visualization of nodes and relationships
- **Query Management**:
  - Manual Cypher queries
  - Predefined queries
  - Admin query management
- **Node Management**:
  - Add new nodes
  - Define relationships
  - Explore node layers
- **Test Analysis**:
  - Test impact analysis
  - Test coverage visualization
  - Test results tracking
- **Theme Support**: Light and dark mode
- **CSRF Protection**: Secure form submissions and API calls

## Prerequisites

- Python 3.9+
- PostgreSQL
- Neo4j Database
- Node.js (for development)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd neo4j_dashboard
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the project root with the following variables:
```env
# Django Settings
SECRET_KEY=your-secret-key
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database Settings
POSTGRES_NAME=neo_dashboard
POSTGRES_USER=neo4j_dashboard_user
POSTGRES_PASSWORD=your-password
POSTGRES_HOST=localhost
POSTGRES_PORT=5432

# Neo4j Settings
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your-password
```

5. Run migrations:
```bash
python manage.py migrate
```

6. Start the development server:
```bash
python manage.py runserver
```

## Project Structure

```
neo4j_dashboard/
├── dashboard/
│   ├── static/
│   │   └── js/
│   │       └── csrf.js
│   ├── templates/
│   │   └── dashboard/
│   │       ├── base.html
│   │       ├── home.html
│   │       └── ...
│   ├── models.py
│   ├── views.py
│   └── urls.py
├── neo4j_dashboard/
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── requirements.txt
└── README.md
```

## Key Components

### Views

- `home`: Main dashboard view
- `manual_queries`: Execute custom Cypher queries
- `predefined_queries`: Manage and execute saved queries
- `add_nodes`: Add new nodes to the graph
- `explore_layers`: Explore node relationships
- `test_impact_analysis`: Analyze test coverage and impact

### Security Features

- CSRF Protection
- Safe Query Validation
- Environment Variable Configuration
- Session Management

### Database Integration

- PostgreSQL for Django backend
- Neo4j for graph database
- Session storage in database

## Usage

1. **Accessing the Dashboard**
   - Open your browser and navigate to `http://localhost:8000`
   - The main dashboard will display available features

2. **Executing Queries**
   - Use the Manual Query interface for custom Cypher queries
   - Access predefined queries from the Predefined Queries section
   - Create and manage queries in the Admin Queries section

3. **Managing Nodes**
   - Add new nodes through the Add Nodes interface
   - Define relationships between nodes
   - Explore node connections using the Explore Layers feature

4. **Test Analysis**
   - View test coverage statistics
   - Analyze test impact on components
   - Track test results and dependencies

## Development

### Adding New Features

1. Create new views in `dashboard/views.py`
2. Add corresponding templates in `dashboard/templates/dashboard/`
3. Update URLs in `dashboard/urls.py`
4. Add any required static files in `dashboard/static/`

### Testing

```bash
python manage.py test
```

### Static Files

Collect static files for production:
```bash
python manage.py collectstatic
```

## Deployment

1. Set `DEBUG=False` in `.env`
2. Configure proper `ALLOWED_HOSTS`
3. Set up a production database
4. Configure a production web server (e.g., Nginx)
5. Use a production-grade WSGI server (e.g., Gunicorn)

## Security Considerations

- Keep your `.env` file secure and never commit it to version control
- Regularly update dependencies
- Monitor Neo4j query performance
- Implement proper access controls
- Use HTTPS in production

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

[Your License Here]

## Support

For support, please [contact information or issue tracker link] 
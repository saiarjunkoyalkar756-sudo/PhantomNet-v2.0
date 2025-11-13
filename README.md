# PhantomNet

## Project Description
PhantomNet is a comprehensive cybersecurity platform designed to provide advanced threat intelligence, analysis, and defense capabilities. It integrates various microservices, a blockchain layer, and a sophisticated AI-driven agent to create a robust and adaptive security ecosystem.

## Setup Instructions

### Prerequisites
*   Python 3.9+
*   Node.js (LTS version recommended)
*   npm (Node Package Manager)

### Backend Setup (Python)
1.  Navigate to the `backend_api` directory:
    ```bash
    cd backend_api
    ```
2.  Install Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: Some dependencies like `scikit-learn` may fail to install in certain environments due to missing compilers. See 'Known Issues' below.)*
3.  Return to the project root:
    ```bash
    cd ..
    ```

### Frontend Setup (React)
1.  Navigate to the `dashboard_frontend` directory:
    ```bash
    cd dashboard_frontend
    ```
2.  Install Node.js dependencies:
    ```bash
    npm install
    ```
3.  Return to the project root:
    ```bash
    cd ..
    ```

## How to Run

### Run Backend
1.  Ensure you are in the project root directory.
2.  Start the FastAPI application:
    ```bash
    uvicorn backend_api.api_gateway.app:app --reload
    ```
    The backend API will typically be available at `http://127.0.0.1:8000`.

### Run Frontend
1.  Ensure you are in the `dashboard_frontend` directory:
    ```bash
    cd dashboard_frontend
    ```
2.  Start the React development server:
    ```bash
    npm start
    ```
    The frontend application will typically be available at `http://localhost:3000`.

## Known Issues

### Python Backend
*   **PermissionError during `pytest`:** Some tests may fail to collect due to a `Permission denied` error on `/phantomnet_agent/red_teaming/playbooks/conftest.py`. This is an environmental issue and could not be resolved.
*   **`scikit-learn` Installation Failure:** The `scikit-learn` library, a dependency for some Python tests, failed to install due to the absence of a Fortran compiler in the environment. This prevents certain tests from running.
*   **Deprecation Warnings:** Several deprecation warnings related to SQLAlchemy, Pydantic, and FastAPI were observed during testing. These indicate areas for future code modernization.

### JavaScript Frontend
*   **`npm install` Warnings/Vulnerabilities:** `npm install` completed with several warnings about deprecated packages and reported 10 vulnerabilities (4 moderate, 6 high). These should be addressed for security and maintainability.
*   **`npm test` Not Executed:** Frontend tests were not executed as the command was repeatedly cancelled.
*   **`npm run build` Failure:** The frontend build consistently fails with a PostCSS/Tailwind CSS configuration error ("It looks like you're trying to use `tailwindcss` directly as a PostCSS plugin..."). This issue could not be resolved and will prevent a successful production build of the frontend.

## Contact
For any questions or further assistance, please refer to the project maintainers.

## License
[Specify project license here]

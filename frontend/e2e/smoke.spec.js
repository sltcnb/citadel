// Citadel frontend smoke flow — fully mocked API (no live backend).
//
//   login  →  empty dashboard  →  open new-case form  →  create  →  case view
//
// Plus a11y checks that the toast (role="status") and inline error-alert
// (role="alert") landmarks the app relies on for accessible feedback exist,
// and that the flow never falls through to the ErrorBoundary fallback.

import { test, expect, DEFAULT_CASE } from './fixtures.js'

async function login(page) {
  await page.goto('/login')
  await page.getByPlaceholder('Enter your username').fill('nbuiss')
  await page.getByPlaceholder('Enter your password').fill('correct horse battery staple')
  await page.getByRole('button', { name: /sign in/i }).click()
}

test('login → empty dashboard → new case → create → case view', async ({ page, apiState }) => {
  await login(page)

  // Landed on the dashboard with an empty case list.
  await expect(page).toHaveURL('/')
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
  await expect(page.getByText('No cases yet')).toBeVisible()

  // We never rendered the app-wide ErrorBoundary fallback.
  await expect(page.getByText('Something went wrong')).toHaveCount(0)

  // Open the new-case form from the top bar and (mock-)create a case.
  await page.getByRole('button', { name: /new case/i }).click()
  const nameInput = page.getByPlaceholder('Case name…')
  await expect(nameInput).toBeVisible()
  await nameInput.fill('Operation Smoke')
  await page.getByRole('button', { name: 'Create', exact: true }).click()

  // The mocked create returns DEFAULT_CASE.case_id → app navigates to the view.
  await expect(page).toHaveURL(new RegExp(`/cases/${DEFAULT_CASE.case_id}$`))
  await expect(page.getByText('Something went wrong')).toHaveCount(0)
})

test('a11y: inline error alert (role="alert") on failed case create', async ({ page, apiState }) => {
  // Force the create call to fail so the inline error box renders.
  apiState.overrides['POST /cases'] = {
    status: 400,
    body: { detail: 'Case name already exists' },
  }

  await login(page)
  await page.getByRole('button', { name: /new case/i }).click()
  await page.getByPlaceholder('Case name…').fill('Dupe')
  await page.getByRole('button', { name: 'Create', exact: true }).click()

  const alert = page.getByRole('alert')
  await expect(alert).toBeVisible()
  await expect(alert).toContainText('Case name already exists')
})

test('a11y: toast (role="status") on failed archive import', async ({ page, apiState }) => {
  // A failed import surfaces an accessible toast (role="status", aria-live).
  apiState.overrides['POST /cases/import/archive'] = {
    status: 500,
    body: { detail: 'Corrupt archive' },
  }

  await login(page)
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()

  // Drive the hidden .citadel file input behind the "Import Archive" button.
  await page.setInputFiles('input[type="file"][accept=".citadel"]', {
    name: 'case.citadel',
    mimeType: 'application/gzip',
    buffer: Buffer.from('not-a-real-archive'),
  })

  const toast = page.getByRole('status')
  await expect(toast).toBeVisible()
})

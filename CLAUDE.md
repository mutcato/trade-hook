# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**trade-hook** is a Django REST Framework application that manages trading webhooks and triggers. It provides:
- User authentication (JWT-based via rest_framework_simplejwt)
- Webhook management (Hook and HookSet models)
- Trade execution triggers with Telegram alerts
- Multi-channel notification system via generic foreign keys (currently Telegram)
- Exchange credential management

**Tech Stack**: Django 6.0.1, Django REST Framework, PostgreSQL, JWT auth, Telegram API

## Getting Started

### Setup
```bash
python -m venv venv
source venv/bin/activate  # or: . venv/Scripts/activate on Windows
pip install -r requirements.txt
```

### Environment Variables
Create or update `.env` in the project root. Key variables:
- `SECRET_KEY`: Django secret key
- `POSTGRES_CONNECTION_STRING`: PostgreSQL connection string (format: `postgresql://user:pass@host:port/dbname`)
- `TELEGRAM_BOT_TOKEN`: Bot token from BotFather (used for alerts)
- `TELEGRAM_BOT_NAME`: Bot username (for display)
- `ACCESS_TOKEN_LIFETIME`, `REFRESH_TOKEN_LIFETIME`: JWT token lifetimes in seconds
- `FREE_EXECUTION_QUOTA`: Lifetime free executions per account (default 3)
- `FRONTEND_BASE_URL`: Used to build the provider's success/cancel return URLs
- `NOWPAYMENTS_API_KEY`, `NOWPAYMENTS_IPN_SECRET`: From the NOWPayments dashboard
- `NOWPAYMENTS_SANDBOX`: Keep `true` to hit `api-sandbox.nowpayments.io` (default `true`)
- `NOWPAYMENTS_IPN_CALLBACK_URL`: Publicly reachable URL for the callback; locally, tunnel it

See `.env.example` for the full list with notes.

### Database Setup
```bash
python manage.py migrate                    # Run all migrations
python manage.py migrate <app_label>       # Run specific app migrations
```

### Running the Development Server
```bash
python manage.py runserver                  # Default: http://127.0.0.1:8000
python manage.py runserver 0.0.0.0:8000    # Listen on all interfaces
```

## Testing

Run all tests:
```bash
python manage.py test
```

Run a specific test module:
```bash
python manage.py test authentication.tests.test_views
python manage.py test trader.tests.test_views
```

Run a specific test class:
```bash
python manage.py test authentication.tests.test_views.RegisterViewTests
```

Run a single test method:
```bash
python manage.py test authentication.tests.test_views.RegisterViewTests.test_user_registration
```

Coverage report:
```bash
coverage run --source='.' manage.py test
coverage report
coverage html  # Generates htmlcov/index.html
```

## Code Architecture

### App Structure
- **authentication**: User registration, login, token management (JWT)
  - Custom `User` model: email-based instead of username
  - `UserManager`: Handles user creation and superuser creation
  - Views: Register, Login, Logout, Token refresh (via SimpleJWT)
  
- **trader**: Core trading/webhook functionality
  - `HookSet`: Collection of webhooks with notification channels and a time window
  - `Hook`: Individual webhook (triggers mark when activated)
  - `Trade`: Trading operations (LONG/SHORT on currency pairs) linked to HookSets
  - `Telegram`: Notification channel destination (stores chat_id)
  - `Exchange`: Exchange credentials (currently unused in API, placeholder for future trade execution)
  - `NotificationTarget`: Generic FK bridge between HookSet and notification channels

- **billing**: Execution credits, paid with crypto
  - `CreditPack`: Purchasable bundle (rows, not constants — priced in the admin)
  - `Wallet`: Per-user balance plus the lifetime free-tier counter
  - `Order`: One top-up attempt against a provider; `credited_at` is the idempotency marker
  - `LedgerEntry`: Append-only audit trail of every credit movement
  - `providers/nowpayments.py`: NOWPayments adapter (non-custodial, hosted invoice, HMAC-signed IPN)
  - `services.py`: The only place credits move — holds the locking and ledger writes

- **core**: Django configuration and URL routing

### Key Design Patterns

**Multi-channel Notifications via GenericForeignKey**
```python
# HookSet can notify any number of channels (Telegram today, Email later)
# through NotificationTarget's GenericForeignKey without schema changes
HookSet.notification_targets → NotificationTarget → (Telegram, Email, etc.)
```
This pattern lets you add new channel types (Email, Slack) without migrating HookSet.

**Hook Triggering Logic**
When a Hook is triggered:
1. Mark it as triggered with a timestamp
2. Check if all sibling hooks in the same HookSet are triggered and within the time window
3. If all conditions met, bill one execution credit then notify all Telegram channels linked to that HookSet
4. Reset the cycle either way, so an unpaid cycle cannot sit armed and fire on the next top-up
5. Time window is stored as a TimeField in HookSet (e.g., 1 hour)

**Credit Metering**
A *completed HookSet* is the billable event — not an individual hook trigger.
`billing.services.consume_execution` spends the free tier
(`settings.FREE_EXECUTION_QUOTA`, default 3) before the paid balance, and the
HookSet's `created_by` is charged rather than whoever called the public webhook.
Out of credits means no alert is sent, but `/hooks/{uuid}/trigger/` still answers
200 (`executed: false`, `reason: "insufficient_credits"`) — an error status would
make external signal sources like TradingView disable the webhook.

**Payment Callbacks**
NOWPayments reports `confirmed` once the chain confirms but *before* the payout is
forwarded, so only `finished` grants credits. Callbacks are authenticated by the
`x-nowpayments-sig` HMAC-SHA512 header over the key-sorted raw body — not by a
token — mirroring how `HookViewSet.trigger` treats its UUID as the credential.

**Serializer Patterns**
ViewSets use different serializers for read vs. write:
- `HookSetSerializer`: Read (full nested details)
- `HookSetCreateUpdateSerializer`: Write (simplified, excludes read-only fields)

### API Endpoints

**Authentication** (`/api/auth/`)
- `POST /register/` — Register new user
- `POST /login/` — Login (returns access + refresh tokens)
- `POST /logout/` — Revoke tokens (blacklist)
- `POST /token/refresh/` — Get new access token

**Trader** (`/api/trader/`)
- `GET/POST /hooksets/` — List/create HookSets
- `GET/PUT/DELETE /hooksets/{id}/` — Detail, update, delete HookSet
- `GET/POST /hooks/` — List/create Hooks
- `POST /hooks/{uuid}/trigger/` — Trigger a hook (custom action)
- `GET/POST /trades/` — List/create Trades
- `GET/POST /telegrams/` — List/create Telegram destinations
- `GET /telegrams/bot_info/` — Get bot name and Telegram link

All trader ViewSets scope `get_queryset()` to `request.user`; `/hooks/{uuid}/trigger/`
is the one deliberate exception, since the public webhook has no authenticated user.

**Billing** (`/api/billing/`)
- `GET /wallet/` — Caller's balance, free tier remaining, total available
- `GET /packs/` — Active credit packs with per-credit price and discount
- `GET/POST /orders/` — List own top-ups / open one (returns `invoice_url` to redirect to)
- `GET /orders/{uuid}/` — Poll a single order (the frontend waits on `credited_at`)
- `GET /ledger/` — Credit history
- `POST /nowpayments/ipn/` — Provider callback; HMAC-signed, unauthenticated

## Common Tasks

### Adding a New Notification Channel (e.g., Email)
1. Create `Email` model with `.send(message)` method (mimic `Telegram.send()`)
2. Register in `INSTALLED_APPS` if in a separate app
3. No HookSet changes needed — `NotificationTarget` handles it via GenericForeignKey
4. Update serializers/views to accept Email in creation endpoints
5. Add tests

### Creating a Migration
```bash
python manage.py makemigrations <app_label>  # Create migration file
python manage.py migrate                      # Apply it
```

### Adding a New Endpoint
1. Define serializer(s) in `trader/serializers.py` (or `authentication/serializers.py`)
2. Add ViewSet in `trader/views.py` with custom `@action` if needed
3. Register router in `trader/urls.py` (or `authentication/urls.py`)
4. Write tests in `trader/tests/test_views.py`

### Debugging Database Issues
```bash
python manage.py sqlmigrate <app_label> <migration_number>  # Preview SQL
python manage.py showmigrations                              # List all migrations
python manage.py dbshell                                     # Open PostgreSQL shell
```

## Notes from Code Review

- **Trade.trigger()** has a TODO comment: actual trade API calls are not yet implemented
- **Exchange model** is defined but not exposed via API or linked to trades (ready for future implementation)
- Telegram bot token is currently in `.env` (safe for development, but use environment-based secrets in production)
- Time window validation and pair validation are in the models; consider moving complex validation to validators if it grows
- **`HookSet.timewindow`** is a `TimeField` with a `timedelta` default, which is invalid — any
  `baker.make(HookSet, ...)` must pass `timewindow` explicitly or the insert raises. Worth fixing
  with a migration at some point.
- **`Exchange.__str__`** returns `self.name`, a field the model does not have

## Important Files Reference

- `core/settings.py` — Django configuration, INSTALLED_APPS, database, JWT settings
- `core/urls.py` — Main URL routing
- `trader/models.py` — Core models (HookSet, Hook, Trade, Telegram, NotificationTarget)
- `trader/views.py` — ViewSets and custom actions
- `trader/serializers.py` — Read/write serializers for all models
- `billing/services.py` — All credit movement (consume, credit an order, apply a callback)
- `billing/providers/nowpayments.py` — The only outbound payment-provider HTTP call
- `authentication/models.py` — User model and UserManager
- `manage.py` — Django management script
- `requirements.txt` — Python dependencies

## Code Style Guidance

Follow the Karpathy behavioral guidelines in `.cursor/rules/karpathy-guidelines.mdc`:
- **Think before coding**: Surface assumptions and tradeoffs, ask before implementing unclear tasks
- **Simplicity first**: No overengineering; only implement what's asked
- **Surgical changes**: Only touch code directly related to the task; don't refactor unrelated code
- **Goal-driven execution**: Define verifiable success criteria; loop until verified

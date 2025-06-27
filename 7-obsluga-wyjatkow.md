# Obsługa wyjątków aplikacyjnych oraz systemowych wraz z ich wpływem na przetwarzanie transakcji

## Spis treści

1. [Architektura obsługi wyjątków w systemie SSBD02](#1-architektura-obsługi-wyjątków-w-systemie-ssbd02)
2. [Obsługa błędów w warstwie frontendowej](#2-obsługa-błędów-w-warstwie-frontendowej)
3. [Wpływ wyjątków na transakcje](#3-wpływ-wyjątków-na-transakcje)
4. [Przykłady praktyczne z systemu](#4-przykłady-praktyczne-z-systemu)
5. [Monitoring i logowanie](#5-monitoring-i-logowanie)
6. [Podsumowanie](#6-podsumowanie)
7. [Powtórzenie - błędy, wyjątki, asercje](#7-wykład---wyjątki-błędy-asercje)
8. [Powtórzenie - wyjatki aplikacyjne i systemowe](#8-wykład---wyjatki-aplikacyjne-i-systemowe)
9. [Obsluga błedów - dokumentacja ssbd](#9-obsługa-błędów---dokumentacja-ssbd)
10. [Wyjatki - dokumentacja ssbd](#10-wyjątki-aplikacyjne)

---

## 1. Architektura obsługi wyjątków w systemie SSBD02

### 1.1 Hierarchia wyjątków aplikacyjnych

System SSBD02 wykorzystuje hierarchiczną strukturę wyjątków opartą na klasie bazowej `AppBaseException`:

```java
package pl.lodz.p.it.ssbd2025.ssbd02.exceptions;

import org.springframework.http.HttpStatusCode;
import org.springframework.web.server.ResponseStatusException;

/**
 * Bazowa klasa dla wszystkich wyjątków aplikacyjnych w systemie.
 * Dziedziczy po ResponseStatusException, co umożliwia automatyczne
 * mapowanie na odpowiednie kody HTTP.
 * 
 * Wszystkie wyjątki aplikacyjne powinny dziedziczyć po tej klasie
 * w celu zapewnienia spójnej obsługi błędów w całym systemie.
 */
public abstract class AppBaseException extends ResponseStatusException {
    
    /**
     * Konstruktor podstawowy dla wyjątków aplikacyjnych
     * @param status Kod statusu HTTP
     * @param reason Opis błędu
     */
    protected AppBaseException(HttpStatusCode status, String reason) {
        super(status, reason);
    }

    /**
     * Konstruktor z przyczynę błędu
     * @param status Kod statusu HTTP
     * @param reason Opis błędu
     * @param cause Przyczyna błędu (wyjątek źródłowy)
     */
    protected AppBaseException(HttpStatusCode status, String reason, Throwable cause) {
        super(status, reason, cause);
    }
    
    /**
     * Zwraca klucz do internacjonalizacji błędu
     * @return Klucz i18n dla tego wyjątku
     */
    public String getI18nKey() {
        return this.getClass().getSimpleName().toLowerCase();
    }
    
    /**
     * Sprawdza czy wyjątek powinien spowodować rollback transakcji
     * @return true jeśli transakcja powinna zostać wycofana
     */
    public boolean shouldRollbackTransaction() {
        return true; // Domyślnie wszystkie wyjątki aplikacyjne powodują rollback
    }
}
```
Przykładowy wyjątek:

```java
package pl.lodz.p.it.ssbd2025.ssbd02.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import pl.lodz.p.it.ssbd2025.ssbd02.utils.consts.ExceptionConsts;

public class AccountAlreadyVerifiedException extends AppBaseException {
    public AccountAlreadyVerifiedException() {
        super(HttpStatusCode.valueOf(HttpStatus.CONFLICT.value()), ExceptionConsts.ACCOUNT_ALREADY_VERIFIED);
    }
}
```

**Przykłady konkretnych wyjątków w systemie:**

- `AccountNotFoundException` - gdy nie znaleziono konta użytkownika
- `ConcurrentUpdateException` - przy konfliktach optimistic locking
- `AccountConstraintViolationException` - przy naruszeniu ograniczeń bazy danych
- `TokenExpiredException` - przy wygaśnięciu tokenu JWT
- `ClientNotFoundException` - gdy nie znaleziono klienta
- `FoodPyramidNotFoundException` - gdy nie znaleziono piramidy żywieniowej


### 1.2 Globalny handler wyjątków

`GeneralControllerExceptionHandler` obsługuje wszystkie typy wyjątków w systemie:

```java
// srcapi/java/pl/lodz/p/it/ssbd2025/ssbd02/utils/handlers/GeneralControllerExceptionHandler.java
@RestControllerAdvice
public class GeneralControllerExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GeneralControllerExceptionHandler.class);

    /**
     * Obsługa wyjątków aplikacyjnych - przekazuje je dalej bez modyfikacji
     */
    @ExceptionHandler(AppBaseException.class)
    public void passThroughAppExceptions(AppBaseException exception, WebRequest request){
        log.warn("Application exception occurred: {} - {}", 
                exception.getClass().getSimpleName(), 
                exception.getReason());
        throw exception;
    }

    /**
     * Obsługa błędów walidacji Bean Validation
     */
    @ExceptionHandler(ConstraintViolationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ResponseBody
    public ResponseEntity<ValidationErrorResponse> onConstraintValidationException(
            ConstraintViolationException e) {
        
        log.warn("Constraint validation failed: {}", e.getMessage());
        
        ValidationErrorResponse error = new ValidationErrorResponse();
        e.getConstraintViolations().forEach(violation -> {
            error.getViolations().add(
                new ValidationErrorResponse.Violation(
                    violation.getPropertyPath().toString(), 
                    violation.getMessage()
                )
            );
        });

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    /**
     * Obsługa błędów integralności danych
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> handleDataIntegrityViolationException(
            DataIntegrityViolationException ex, WebRequest request) {
        
        log.error("Data integrity violation: {}", ex.getMessage());
        
        Throwable cause = ex.getCause();
        String errorMessage = "Data integrity constraint violation";
        String errorCode = "DATA_INTEGRITY_VIOLATION";

        if (cause instanceof org.hibernate.exception.ConstraintViolationException constraintEx) {
            String violation = constraintEx.getMessage();
            
            if (violation.contains("account_login_key")) {
                errorMessage = "Login is already in use";
                errorCode = "LOGIN_ALREADY_EXISTS";
            } else if (violation.contains("account_email_key")) {
                errorMessage = "Email is already in use";
                errorCode = "EMAIL_ALREADY_EXISTS";
            } else if (violation.contains("food_pyramid_name_key")) {
                errorMessage = "Food pyramid name is already in use";
                errorCode = "PYRAMID_NAME_EXISTS";
            }
        }
        
        Map<String, Object> errorResponse = createErrorResponse(
            HttpStatus.CONFLICT, errorMessage, errorCode
        );
        
        return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
    }

    /**
     * Obsługa błędów autoryzacji
     */
    @ExceptionHandler(AuthorizationDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ResponseEntity<Map<String, Object>> handleAuthorizationException(
            RuntimeException exception, WebRequest webRequest, HttpServletRequest request){
        
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z");
        String formattedDate = ZonedDateTime.now().format(formatter);
        String calledBy = request.getUserPrincipal() != null ? 
            request.getUserPrincipal().getName() : "--ANONYMOUS--";
        
        String logMessage = String.format(
            "[AUTH LOGGER] [%s] User: %s attempted to access resource %s without permission",
            formattedDate, calledBy, request.getRequestURL().toString()
        );
        
        log.warn(logMessage);
        
        Map<String, Object> errorResponse = createErrorResponse(
            HttpStatus.FORBIDDEN,
            "Access denied: insufficient privileges",
            "ACCESS_DENIED"
        );
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
    }
}
```

### 1.3 Interceptory do obsługi wyjątków

#### 1.3.1 Interceptor obsługi Optimistic Locking

```java
// srcapi/java/pl/lodz/p/it/ssbd2025/ssbd02/interceptors/GenericOptimisticLockHandlingInterceptor.java
@Aspect
@Order(Ordered.LOWEST_PRECEDENCE - 100)
@Component
public class GenericOptimisticLockHandlingInterceptor {

    private static final Logger log = LoggerFactory.getLogger(GenericOptimisticLockHandlingInterceptor.class);

    @AfterThrowing(pointcut = "Pointcuts.allRepositoryMethods()", throwing = "olfe")
    public void handleOptimisticLockException(JoinPoint joinPoint, OptimisticLockingFailureException olfe) {
        String methodName = joinPoint.getSignature().getName();
        String className = joinPoint.getTarget().getClass().getSimpleName();
        
        log.warn("Optimistic locking failure in {}.{}: {}", 
                className, methodName, olfe.getMessage());
        
        // Konwersja na aplikacyjny wyjątek ConcurrentUpdateException
        throw new ConcurrentUpdateException(olfe);
    }
}
```

**Przykład działania w systemie:**
Gdy dwóch dietetyków próbuje jednocześnie zaktualizować raport badań krwi klienta, drugi otrzyma `ConcurrentUpdateException`.

#### 1.3.2 Interceptor obsługi naruszeń ograniczeń

```java
// srcapi/java/pl/lodz/p/it/ssbd2025/ssbd02/interceptors/AccountConstraintViolationsHandlingInterceptor.java
@Aspect 
@Order(Ordered.LOWEST_PRECEDENCE - 100)
@Component
public class AccountConstraintViolationsHandlingInterceptor {

    private static final Logger log = LoggerFactory.getLogger(AccountConstraintViolationsHandlingInterceptor.class);

    @AfterThrowing(pointcut = "Pointcuts.allRepositoryMethods()", throwing = "dive")
    public void handleDataIntegrityViolationException(DataIntegrityViolationException dive) {
        String errorMessage = dive.getMessage();
        
        log.warn("Data integrity violation detected: {}", errorMessage);
        
        if (errorMessage.contains("account_login_key")) {
            log.warn("Attempt to create account with duplicate login");
            throw new AccountConstraintViolationException(
                ExceptionConsts.ACCOUNT_CONSTRAINT_VIOLATION + ": login already in use"
            );
        } 
        else if (errorMessage.contains("account_email_key")) {
            log.warn("Attempt to create account with duplicate email");
            throw new AccountConstraintViolationException(
                ExceptionConsts.ACCOUNT_CONSTRAINT_VIOLATION + ": email already in use"
            );
        } 
        else if (errorMessage.contains("food_pyramid_name_key")) {
            log.warn("Attempt to create food pyramid with duplicate name");
            throw new FoodPyramidNameAlreadyInUseException(
                ExceptionConsts.FOOD_PYRAMID_NAME_ALREADY_IN_USE
            );
        }
        else {
            log.error("Unrecognized data integrity violation: {}", errorMessage);
            throw new AccountConstraintViolationException(dive);
        }
    }
}
```

**Przykład działania w systemie:**
Gdy admin próbuje utworzyć konto z emailem, który już istnieje w systemie, interceptor konwertuje `DataIntegrityViolationException` na `AccountConstraintViolationException`.

---

## 2. Obsługa błędów w warstwie frontendowej

### 2.1 Klient API z automatyczną obsługą błędów

```typescript
// srcweb/lib/apiClient.ts
export const apiClient = axios.create({
  baseURL: "/api",
  headers: {
    "Content-Type": "application/json",
  },
  withCredentials: true,
  timeout: 30000,
})

// Interceptor żądań - automatyczne dodawanie tokenu
apiClient.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const token = localStorage.getItem("token")
    if (token) {
      config.headers["Authorization"] = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    console.error("[API Request Error]", error)
    return Promise.reject(error)
  },
)

// Interceptor odpowiedzi - obsługa błędów i odświeżanie tokenów
apiClient.interceptors.response.use(
  (response: AxiosResponse) => {
    return response
  },
  async (error: AxiosError) => {
    const originalRequest = error.config

    // Obsługa błędów autoryzacji (401)
    if (error.response && error.response.status === 401 && originalRequest && !originalRequest._retry) {
      if (window.location.pathname.includes("/login")) {
        localStorage.removeItem("token")
        return Promise.reject(error)
      }

      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject })
        })
          .then((token) => {
            if (originalRequest.headers) {
              originalRequest.headers["Authorization"] = `Bearer ${token}`
            }
            return apiClient(originalRequest)
          })
      }

      originalRequest._retry = true
      isRefreshing = true

      try {
        console.log("[Token Refresh] Attempting to refresh expired token")
        const refreshRes = await authClient.post("/account/refresh")
        const { value } = refreshRes.data

        localStorage.setItem("token", value)
        apiClient.defaults.headers.common["Authorization"] = `Bearer ${value}`

        console.log("[Token Refresh] Token refreshed successfully")
        processQueue(null, value)

        if (originalRequest.headers) {
          originalRequest.headers["Authorization"] = `Bearer ${value}`
        }
        return apiClient(originalRequest)
      } catch (refreshError) {
        console.error("[Token Refresh] Failed to refresh token:", refreshError)
        processQueue(refreshError, null)
        localStorage.removeItem("token")

        if (!window.location.pathname.includes("/login")) {
          window.location.href = "/login"
        }

        return Promise.reject(refreshError)
      } finally {
        isRefreshing = false
      }
    }

    return Promise.reject(error)
  },
)
```

### 2.2 Centralizowany handler błędów

```typescript
// srcweb/lib/axiosErrorHandler.ts
import axios from "axios";
import i18n from "@/i18n";
import { toast } from "sonner";

export const axiosErrorHandler = (
  error: unknown,
  fallbackMessage = "unexpected"
) => {
  if (axios.isAxiosError(error)) {
    const status = error.response?.status;

    if (status === 500) {
      toast.error(i18n.t("exceptions.unexpected"));
      return;
    }

    const message =
      error.response?.data?.message ||
      error.response?.data?.error ||
      fallbackMessage;

    toast.error(i18n.t("exceptions." + message));
  }
};
```

---

## 3. Wpływ wyjątków na transakcje

### 3.1 Interceptor logowania transakcji

```java
// srcapi/java/pl/lodz/p/it/ssbd2025/ssbd02/interceptors/TransactionLoggingInterceptor.java
@Aspect 
@Order(Ordered.LOWEST_PRECEDENCE)
@Component
public class TransactionLoggingInterceptor {

    private static final Logger log = LoggerFactory.getLogger(TransactionLoggingInterceptor.class);

    @Before("Pointcuts.transactionLoggedAnnotatedMethods()")
    public void registerSynchronization() throws Throwable {
        
        final String transactionId = createTransactionId();

        TransactionSynchronizationLogger logger = 
            TransactionSynchronizationLogger.threadLocalTSLogger.get();

        if (logger == null) {
            logger = new TransactionSynchronizationLogger();
        }

        logger.setTransactionId(transactionId);
        
        TransactionSynchronizationManager.registerSynchronization(logger);
        
        log.trace("[TRANSACTION LOGGER] Transaction synchronization: {} registered", 
                 logger.getTransactionId());
    }

    private String createTransactionId() {
        String transactionName = TransactionSynchronizationManager.getCurrentTransactionName();
        String threadId = String.valueOf(Thread.currentThread().threadId());
        
        StringBuilder idBuilder = new StringBuilder();
        idBuilder.append(transactionName != null ? transactionName : "UNKNOWN");
        idBuilder.append(":");
        idBuilder.append(threadId);
        
        if (RetrySynchronizationManager.getContext() != null) {
            int retryCount = RetrySynchronizationManager.getContext().getRetryCount();
            idBuilder.append(" (retry #").append(retryCount).append(")");
        }
        
        return idBuilder.toString();
    }
}
```

### 3.2 Konfiguracja transakcji w serwisach

**Przykład z AccountService:**

```java
// srcapi/java/pl/lodz/p/it/ssbd2025/ssbd02/mok/service/implementations/AccountService.java
@Service
@Transactional(rollbackFor = {AppBaseException.class, RuntimeException.class})
public class AccountService implements IAccountService {
    
    @Transactional(readOnly = true)
    public AccountWithRolesDTO getMe() {
        // Operacja tylko do odczytu - optymalizacja
    }
    
    @Transactional(rollbackFor = {AppBaseException.class})
    public void updateAccount(UpdateAccountDTO updateAccountDTO, String lockToken) {
        // Operacja zapisu z automatycznym rollback dla wyjątków aplikacyjnych
        try {
            Account account = findAccountByLogin(getCurrentUserLogin());
            // Aktualizacja danych...
            accountRepository.save(account);
        } catch (OptimisticLockingFailureException e) {
            // Zostanie przechwycone przez interceptor i skonwertowane na ConcurrentUpdateException
            throw e;
        }
    }
}
```

---

## 4. Przykłady praktyczne z systemu

### 4.1 Obsługa błędów w formularzu zmiany danych

```typescriptreact
// srcweb/components/changeDataForm.tsx
export function ChangeDataForm({
  firstName,
  lastName,
  lockToken,
}: ChangeDataFormProps) {
  const { t } = useTranslation();
  const updateMeDataMutation = useChangeMeData();
  const [isDataDialogOpen, setIsDataDialogOpen] = useState(false);
  const [pendingData, setPendingData] = useState<{
    firstName?: string;
    lastName?: string;
  } | null>(null);

  const form = useForm({
    resolver: zodResolver(personalDataSchema),
    defaultValues: {
      firstName,
      lastName,
    },
  });

  function onSubmit(values: z.infer<typeof personalDataSchema>) {
    setPendingData(values);
    setIsDataDialogOpen(true);
  }

  const confirmDataChange = () => {
    if (pendingData && pendingData.firstName && pendingData.lastName) {
      updateMeDataMutation.mutate(
        {
          firstName: pendingData.firstName,
          lastName: pendingData.lastName,
          lockToken: lockToken,
        },
        {
          onError: (error) => {
            // Automatyczna obsługa błędów przez axiosErrorHandler w hook'u
            console.error("Failed to update data:", error);
          },
          onSuccess: () => {
            toast.success(t("profile.data_updated_successfully"));
            setIsDataDialogOpen(false);
            setPendingData(null);
          }
        }
      );
    }
  };

  return (
    <>
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
          <FormField
            control={form.control}
            name="firstName"
            render={({ field }) => (
              <FormItem>
                <RequiredFormLabel htmlFor="firstName">
                  {t("profile.fields.firstName")}
                </RequiredFormLabel>
                <FormControl>
                  <Input
                    placeholder={t("profile.fields.firstName")}
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          {/* Podobnie dla lastName */}
          <Button type="submit" className="w-full">
            {t("common.save")}
          </Button>
        </form>
      </Form>
      
      <AlertDialog open={isDataDialogOpen} onOpenChange={setIsDataDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("admin.user_account.forms.confirm_data_change_title")}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t("profile.fields.confirm_data_change_description")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>
              {t("admin.user_account.forms.cancel")}
            </AlertDialogCancel>
            <AlertDialogAction onClick={confirmDataChange}>
              {t("admin.user_account.forms.save_personal_data")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
```

**Scenariusz błędu:**

1. Użytkownik wypełnia formularz zmiany danych
2. Ktoś inny aktualizuje te same dane (zmienia się `lockToken`)
3. Backend rzuca `ConcurrentUpdateException`
4. Frontend otrzymuje błąd 409 i wyświetla odpowiedni komunikat


### 4.2 Obsługa błędów w formularzu ankiety okresowej

```typescriptreact
// srcweb/components/submitPeriodicSurveyForm.tsx
export function SubmitPeriodicSurveyForm() {
  const { t } = useTranslation();
  const submitSurveyMutation = useSubmitPeriodicSurvey();
  const [isSubmitDialogOpen, setIsSubmitDialogOpen] = useState(false);

  const form = useForm({
    resolver: zodResolver(periodicSurveySchema),
    defaultValues: {
      weight: undefined,
      bloodPressure: "",
      bloodSugarLevel: undefined,
    },
  });

  function onSubmit() {
    setIsSubmitDialogOpen(true);
  }

  const confirmSubmit = () => {
    const formData = form.getValues();

    submitSurveyMutation.mutate(
      formData,
      {
        onError: (error) => {
          // Hook automatycznie obsługuje błędy przez axiosErrorHandler
          if (error.response?.status === 400) {
            // Błędy walidacji - mogą być wyświetlone przy polach
            console.error("Validation errors:", error.response.data);
          } else if (error.response?.data?.message === "periodic_survey_too_soon") {
            toast.error(t("exceptions.periodic_survey_too_soon"));
          }
        },
        onSuccess: () => {
          toast.success(t("periodic_survey.form.submitted_successfully"));
          setIsSubmitDialogOpen(false);
          form.reset();
        }
      }
    );
  };

  return (
    <div className="container max-w-2xl mx-auto py-8">
      <Card>
        <CardHeader>
          <CardTitle>
            {t("periodic_survey.form.title")}
          </CardTitle>
          <CardDescription>
            {t("periodic_survey.form.description")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <FormField
                control={form.control}
                name="weight"
                render={({ field }) => (
                  <FormItem>
                    <RequiredFormLabel htmlFor="weight">
                      {t("periodic_survey.form.label.weight")}
                    </RequiredFormLabel>
                    <FormControl>
                      <Input
                        type="number"
                        {...field}
                        onChange={(e) =>
                          field.onChange(Number.parseFloat(e.target.value) || 0)
                        }
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              {/* Podobnie dla innych pól */}
              <Button type="submit" className="w-full">
                {t("periodic_survey.form.submit_button")}
              </Button>
            </form>
          </Form>
        </CardContent>
      </Card>
      
      <AlertDialog open={isSubmitDialogOpen} onOpenChange={setIsSubmitDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("periodic_survey.form.submit_alert_title")}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t("periodic_survey.form.submit_alert_description")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>
              {t("common.cancel")}
            </AlertDialogCancel>
            <AlertDialogAction onClick={confirmSubmit}>
              {t("periodic_survey.form.submit_button")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
```

**Scenariusze błędów:**

1. **Zbyt częste wypełnianie ankiety** - backend rzuca `PeriodicSurveyTooSoonException`
2. **Błędy walidacji** - nieprawidłowe wartości ciśnienia krwi
3. **Brak uprawnień** - klient nie ma przypisanego dietetyka


### 4.3 Obsługa błędów w raportach badań krwi

```typescriptreact
// srcweb/components/blood-test-reports.tsx
export default function BloodTestReports({ userRole }: BloodTestReportsProps) {
  const { clientId } = useParams<{ clientId: string }>()

  const clientQuery = useClientBloodTestReports(userRole === "client");
  const dieticianQuery = useClientBloodTestByDieticianReports(
      userRole === "dietician" ? clientId : undefined
  );

  const query = userRole === "client" ? clientQuery : dieticianQuery;
  const { data: reports, isLoading, isError, refetch } = query;

  const updateReportMutation = useUpdateBloodTestReport(refetch, () => {
    setIsEditModalOpen(false);
    setIsConfirmModalOpen(false);
    setEditingReport(null);
    setPendingUpdatedReport(null);
  });

  if (isError) {
    const axiosError = query.error as AxiosError<{ message: string }>;
    const errorMessage = axiosError?.response?.data?.message;

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4 }}
            className="max-w-4xl mx-auto p-6"
        >
          {errorMessage === "client_blood_test_report_not_found" ? (
              <p className="text-red-500">
                {t("blood_test_reports.client_blood_test_report_not_found")}
              </p>
          ) : errorMessage === "permanent_survey_not_found" ? (
              <p className="text-red-500">
                {t("blood_test_reports.permanent_survey_not_found")}
              </p>
          ) : (
              <p className="text-red-500">
                {t("blood_test_reports.error_loading_reports")}
              </p>
          )}
        </motion.div>
    );
  }

  const handleConfirmSave = () => {
    if (pendingUpdatedReport) {
      updateReportMutation.mutate(pendingUpdatedReport, {
        onError: (error) => {
          if (error.response?.status === 409) {
            toast.error(t("exceptions.concurrent_update_exception"));
          } else if (error.response?.data?.message === "dietician_access_denied") {
            toast.error(t("exceptions.dietician_access_denied"));
          } else {
            axiosErrorHandler(error, "update_failed");
          }
        },
        onSuccess: () => {
          toast.success(t("blood_test_reports.report_updated_successfully"));
        }
      });
    }
  };

  // Reszta komponentu...
}
```

**Scenariusze błędów:**

1. **Brak raportu** - `ClientBloodTestReportNotFoundException`
2. **Brak ankiety stałej** - `PermanentSurveyNotFoundException`
3. **Brak dostępu dietetyka** - `DieticianAccessDeniedException`
4. **Konflikt optimistic locking** - `ConcurrentUpdateException`


---

## 5. Monitoring i logowanie

### 5.1 Przykłady logowania w systemie

**W serwisach:**

```java
// srcapi/java/pl/lodz/p/it/ssbd2025/ssbd02/mok/service/implementations/AccountService.java
@Service
@Transactional
public class AccountService implements IAccountService {
    
    private static final Logger log = LoggerFactory.getLogger(AccountService.class);
    
    @Override
    @MethodCallLogged
    @TransactionLogged
    public void updateAccount(UpdateAccountDTO updateAccountDTO, String lockToken) {
        log.debug("Updating account for user: {}", getCurrentUserLogin());
        
        try {
            Account account = findAccountByLogin(getCurrentUserLogin());
            
            if (!lockTokenService.verifyLockToken(lockToken, account)) {
                log.warn("Invalid lock token for account update: {}", getCurrentUserLogin());
                throw new InvalidLockTokenException();
            }
            
            account.setFirstName(updateAccountDTO.getFirstName());
            account.setLastName(updateAccountDTO.getLastName());
            
            Account savedAccount = accountRepository.save(account);
            log.info("Account updated successfully for user: {}", getCurrentUserLogin());
            
        } catch (OptimisticLockingFailureException e) {
            log.warn("Optimistic locking failure for account: {}", getCurrentUserLogin());
            throw e; // Zostanie przechwycone przez interceptor
        }
    }
}
```

**W interceptorach:**

```java
// srcapi/java/pl/lodz/p/it/ssbd2025/ssbd02/interceptors/GenericOptimisticLockHandlingInterceptor.java
@AfterThrowing(pointcut = "Pointcuts.allRepositoryMethods()", throwing = "olfe")
public void handleOptimisticLockException(JoinPoint joinPoint, OptimisticLockingFailureException olfe) {
    String methodName = joinPoint.getSignature().getName();
    String className = joinPoint.getTarget().getClass().getSimpleName();
    
    log.warn("Optimistic locking failure in {}.{}: {}", 
            className, methodName, olfe.getMessage());
    
    throw new ConcurrentUpdateException(olfe);
}
```

### 5.2 Logowanie w frontendzie

```typescript
// srcweb/lib/apiClient.ts
apiClient.interceptors.response.use(
  (response: AxiosResponse) => {
    if (process.env.NODE_ENV === "development") {
      console.log(`[API Response] ${response.status} ${response.config.url}`, {
        data: response.data,
        headers: response.headers,
      })
    }
    return response
  },
  async (error: AxiosError) => {
    const errorDetails = createErrorDetails(error)
    console.error("[API Response Error]", errorDetails)
    
    // Różne typy logowania w zależności od błędu
    if (isNetworkError(error)) {
      console.error("Network error detected - server may be unavailable")
    } else if (isTimeoutError(error)) {
      console.error("Request timeout - server is taking too long to respond")
    }
    
    return Promise.reject(error)
  },
)
```

---

## 6. Podsumowanie

System SSBD02 implementuje kompleksową obsługę wyjątków na wszystkich warstwach:

### Backend (Java/Spring Boot):

- **Hierarchiczna struktura wyjątków** - `AppBaseException` jako klasa bazowa dla wszystkich wyjątków aplikacyjnych
- **Globalny handler** - `GeneralControllerExceptionHandler` obsługuje wszystkie typy wyjątków
- **Interceptory AOP** - automatyczna konwersja wyjątków systemowych:

- `GenericOptimisticLockHandlingInterceptor` - obsługa konfliktów optimistic locking
- `AccountConstraintViolationsHandlingInterceptor` - obsługa naruszeń ograniczeń bazy danych
- `TransactionLoggingInterceptor` - logowanie cyklu życia transakcji





### Frontend (React/TypeScript):

- **Interceptory Axios** - automatyczna obsługa błędów HTTP i odświeżanie tokenów w `apiClient.ts`
- **Centralizowany handler** - `axiosErrorHandler.ts` dla spójnej obsługi błędów
- **Toast notifications** - przyjazne komunikaty dla użytkownika z internacjonalizacją
- **Komponenty z obsługą błędów** - `changeDataForm.tsx`, `submitPeriodicSurveyForm.tsx`, `blood-test-reports.tsx`


### Konkretne scenariusze w systemie:

1. **Rejestracja konta z duplikatem email** - `AccountConstraintViolationException`
2. **Jednoczesna edycja raportu badań** - `ConcurrentUpdateException`
3. **Zbyt częste wypełnianie ankiety** - `PeriodicSurveyTooSoonException`
4. **Brak dostępu dietetyka do klienta** - `DieticianAccessDeniedException`
5. **Wygaśnięcie tokenu JWT** - automatyczne odświeżanie lub przekierowanie na login


### Transakcje:

- **Automatyczny rollback** - dla wszystkich wyjątków aplikacyjnych (`AppBaseException`)
- **Optimistic locking** - kontrola współbieżności z automatyczną obsługą konfliktów
- **Logowanie transakcji** - monitoring rozpoczęcia, zatwierdzenia i rollback


System zapewnia niezawodność, spójność danych i wysoką jakość doświadczenia użytkownika poprzez graceful handling wszystkich typów błędów.

## 7. Wykład - wyjątki, błędy, asercje

### Przykłady błędów w trakcie wykonania kodu programu
- Zły format danych podanych przez użytkownika,
- Niekompletność danych wejściowych metody lub konstruktora,
- Niestabilna praca systemu operacyjnego lub maszyny wirtualnej JVM,
- Niedostępność wymaganych zasobów systemowych (sprzętowych lub logicznych) np. pamięć stosu lub sterty,
- Niepoprawne działanie części programu, np.
- - niepoprawne wartości argumentów wywołania metody lub konstruktora
- - niepoprawne działania arytmetyczne
- - wywołanie metody nieistniejącego obiektu
- - dwołanie do nieistniejącego elementu tablicy
- - niepoprawne rzutowanie

### Reakcje oprogramowania na wystąpienie błędu
#### Reakcja oprogramowania na wystąpienie błędu powinna uwzględnić:
- automatyczny powrót do bezpiecznego stanu i kontynuowanie przetwarzania danych (tzw. wybrnięcie z błędu) – nie jest możliwe dla każdego typu błędu.
- zakończenie działania akcji lub całego programu z wcześniejszym przedstawieniem użytkownikowi czytelnej informacje o wystąpieniu błędu oraz zwrócić niezerowy kod błędu do systemu operacyjnego (dotyczy zakończenia procesu). Dodatkowo można zapewnić ochronę danych użytkownika przed utratą np. można automatycznie zapisać bieżący stan (chroniąc dane użytkowników) i dopiero wówczas zakończyć działanie programu.

W żadnym przypadku nie należy ignorować błędu pozwalając na utratę informacji o jego wystąpieniu, ponieważ błąd może być trudny do powtórzenia (niepowtarzalny), a do rozwiązania problemu niezbędna jest historia działania aplikacji. Najprostszym sposobem utrwalenia informacji o błędzie jest zapis w dzienniku zdarzeń. Zalecane informowanie użytkownika w czytelny sposób o wystąpieniu błędu. Jeżeli jest to możliwe, wówczas można użytkownikowi przedstawić przyczyny wystąpienia błędu wraz z krótką instrukcją co do dalszych działań mających na celu ich eliminację.

### Sytuacje błędów
Pojawienie się błędów w trakcie wykonania instrukcji kodu programu może wpływać na wyniki wykonanych operacji, zmniejszając niezawodność oprogramowania. Błąd/problem może występować w części programu lub w środowisku, w którym program został uruchomiony. Błędy można także klasyfikować w trakcie tworzenia programu jako przewidywalne lub nieprzewidywalne (np. w zależności od powtarzalności wystąpienia w kolejnych uruchomieniach programu).
Język programowania Java zapewnia dedykowany mechanizm wyjątków, który oferuje przekazywanie informacji o wystąpieniu problemu/nietypowego zdarzenia lub błędu w trakcie wykonania programu oraz umożliwia określenie operacji jakie mają być wykonane w celu skorygowania działania programu w zaistniałej sytuacji.
Obiekt wyjątku reprezentuje zbiór informacji o wykrytym problemie, zaistniałym nietypowym zdarzeniu lub błędzie, przesłany od źródła do odbiorcy wyjątku w wykonywanym programie Java. Załączone do wyjątku informacje powinny ułatwiać wybrnięcie z błędu lub jego obsługę.

### Podstawowe operacje na wyjątkach
W języku programowania Java wyjątek (exception) jest obiektem klasy przynależącej do ustalonej hierarchii. Zwykle typ obiektu wyjątku wystarcza do zidentyfikowania i rozwiązania zaistniałego problemu. Obiekt wyjątku może także zawierać dodatkowe informacje o zaistniałej sytuacji: np. komunikat czy wskazanie na obiekt zgodny z typem java.lang.Throwable będący przyczyną zgłoszenia wyjątku (cause).
#### Podstawowe operacje realizowane z wykorzystaniem obiektu wyjątku:
- utworzenie obiektu wyjątku,
- zgłoszenie wyjątku określonego typu zwykle sygnalizuje wystąpienie konkretnej sytuacji błędu, operację zgłoszenia wyjątku określa się popularnie jako rzucenie wyjątku (throw), zgłoszenie wyjątku rozpoczyna jego propagację,
- przechwycenie i obsłużenie wyjątku jest realizowane poprzez odszukanie odpowiedniego segmentu obsługi wyjątku zawierającego ciąg operacji jakie zostaną wykonane w celu skorygowania zaistniałego błędu, operację przechwycenia wyjątku określa się też jako złapanie wyjątku (catch). Segment obsługi jest określany dla konkretnego typu wyjątków.

### Tworzenie obiektów wyjątków
- Typ instancji wyjątku określa zakres pól i metod jakie udostępnia wyjątek np. w celu zapewnienia wystarczających informacji do diagnostyki przyczyn jego zgłoszenia.
- Tworząc obiekt wyjątku należy precyzyjnie dobierać jego typ w zależności od zastosowań. Brak istniejącej klasy dedykowanej dla wymaganych zastosowań może powodować konieczność utworzenia nowej klasy wyjątku (zapewnia odpowiedni dobór metod i pól klasy do potrzeb obsługi zgłoszonego obiektu wyjątku).
- Klasa obiektu wyjątku musi należeć do hierarchii wyjątków.
- Typ obiektu wyjątku decyduje o doborze segmentu obsługi.
- Dla różnych sytuacji błędów/problemów oprogramowanie powinno zgłaszać wyjątki innego typu.
- Każdy obiekt wyjątku zawiera podstawowe informacje z chwili jego utworzenia (np. zawartość stosu), dlatego w kodzie programu istotna jest lokalizacja instrukcji tworzącej obiekt wyjątku.

### Zgłoszenie wyjątku
- Może być realizowane jedynie dla obiektu typu ustalanego przez klasę należącą do hierarchii wyjątków. Zarówno zgłoszenie jak i propagacja nie zmienia typu obiektu wyjątku.
- Dla obiektu wyjątku zgłoszenie wyjątku (tzw. rzucenie) wyjątku może być realizowane wielokrotnie. Wyróżnia się zgłoszenie jawne (z użyciem instrukcji throw) lub niejawnie (przez JVM).
- Zmienia zasady sterowania przebiegiem programu. Zgłoszenie wyjątku powoduje brak ukończenia wykonania bloku instrukcji. W wyniku niejawnego zgłoszenia kolejne instrukcje w bloku nie zostaną wykonane.
- Rozpoczyna propagację wyjątku, którą kończy przechwycenie wyjątku przez pierwszy napotkany segment obsługi, który jest zgodny z typem obiektu wyjątku. Jeżeli przed przechwyceniem wyjątku zostanie zgłoszony inny wyjątek, wówczas rozpoczyna się propagacja ostatni zgłoszonego wyjątku, a poprzednio zgłoszony wyjątek nie zostanie przechwycony i obsłużony.
- Utworzenie i zgłoszenie wyjątku może być realizowane w ramach jednej instrukcji.

### Przechwytywanie i obsługa wyjątku
#### Przechwycenie zgłoszonego obiektu wyjątku:
- bazuje na doborze odpowiedniego segmentu obsługi względem typu i najbliższego dla lokalizacji zgłoszenia wyjątku względem otaczania dynamicznego bloków kodu.
- wymaga zgodności typu wyjątku z typem wyjątku przypisanym do segmentu obsługi.
- nie powoduje zmiany typu wyjątku.
- rozpoczyna wykonywanie instrukcji zlokalizowanych w segmencie obsługi wyjątku.
#### Obsługa zgłoszonego obiektu wyjątku:
- bazuje na wykonaniu instrukcji zlokalizowanych w segmencie obsługi wyjątku.
- kończy propagację wyjątku.
- może spowodować kolejne zgłoszenie wyjątku.

### Odpowiedzialność programisty
- Oprogramowanie bez implementacji obsługi błędów nie może być uznane za kompletne. Wersja finalna oprogramowania powinna zawierać obsługę błędów, w przypadku Javy dotyczy min. przechwycenia i obsługi zgłoszonych wyjątków.
- Tworząc kod zawsze należy uwzględnić problemy i błędy, które będą sygnalizowane poprzez zgłoszenie wyjątku. Precyzyjnie należy dobierać w kodzie lokalizacje utworzenia, zgłoszenia, przechwycenia i obsługi wyjątku.
- Dobór typu dla tworzonego obiektu wyjątku powinien uwzględniać jego przeznaczenie, dla własnych wyjątków należy tworzyć osobne klasy. Zaleca się wydzielanie klas wyjątków w osobnych pakietach.
- Należy analizować ścieżki propagacji wyjątku (od zgłoszenia do przechwycenia) odpowiednio zamieszczając w kodzie segmenty obsługi wyjątków.
- Dla każdego zgłoszonego wyjątku należy zapewnić segment obsługi, tak by żaden zgłoszony wyjątek nie był przechwycony i obsłużony przez JVM z zastosowaniem domyślnej procedury obsługi.

### Hierarchia klas wyjątków
#### W języku programowania Java typem bazowym dla wszystkich wyjątków jest klasa java.lang.Throwable implementująca interfejs java.io.Serializable.
![Rys. 17.1](/img/7.1.png)

### Podstawowe metody obiektu klasy java.lang.Throwable
- String getMessage() – przekazuje opis komunikatu wyjątku,
- String getLocalizedMessage() – przekazuje dostosowany do lokalizacji opis komunikatu błędu dla wyjątku,
- Throwable getCause() – zwraca wyjątek będący przyczyną zgłoszenia innego wyjątku,
- Throwable initCause(Throwable cause) – ustala inny obiekt wyjątku będący przyczyną zgłoszenia wyjątku,
- void printStackTrace() – wyświetla na standardowym wyjściu zawartość stosu programu z chwili utworzenia wyjątku, utworzenie obiektu wyjątku nie jest to równoznaczne ze zgłoszeniem wyjątku,
- StackTraceElement[] getStackTrace() – dostarcza elementy do analizy stosu (wywołania metod w ramach otaczania dynamicznego) – dostępne od Java SE 1.4

### Jawne zgłoszenie wyjątku
Zgłoszenie wyjątku wymaga reprezentującego go obiektu. Przykład tworzenia i jawnego zgłaszania wyjątku w jednej instrukcji:

```java
{ …
  throw new UnsupportedOperationException(”Komunikat”);
} //uwaga: brak throw nie spowoduje błędu składniowego
```
Jawne zgłoszenie wyjątku musi być ostatnią instrukcją w bloku, a zastosowanie statycznego zagnieżdżenia bloków instrukcji nie eliminuje tej zasady.

```java
{ 

//statyczne zagnieżdżadnie bloków bez instrukcji if
//spowoduje błąd składniowy,

if (obj==null) {

…

throw new NullPointerException(”Brak inicjalizacji”

+” obiektu typu ”+obj.getClass.getSimpleName());

}

…

throw new InternalError(“Ogólny błąd aplikacji”);

}
```

### Zgłoszenie wyjątku
Jawne zgłoszenie wyjątku wymaga użycia instrukcji throw, w której należy określić obiekt zgłaszanego wyjątku, który może być utworzony wcześniej. Instrukcja throw musi być ostatnią instrukcją zamieszczoną w bloku:

```java
{ //utworzenie obiektu wyjątku

Exception ex = new UnsupportedOperationException();

…

throw ex; //jawne zgłoszenie wyjątku

}
```

Niejawne zgłoszenie wyjątku może nastąpić w trakcie wykonania dowolnej instrukcji. Zgłoszenie wyjątku powoduje natychmiastowe przerwanie wykonywania kolejnych instrukcji w bieżącym bloku, wówczas sterowanie wykonaniem programu przekazywane jest do poza bieżący blok.
W przypadku metody, która deklaruje typ dla zwracanego wyniku wystąpienie wyjątku może spowodować zakończenie przetwarzania kodu metody bez zwrócenia wartości końcowej. Zgłoszenie wyjątku przez jedną z zawartych w konstruktorze instrukcji może skutkować nieutworzeniem obiektu.


### Wyjątki środowiska uruchomieniowego
Wyjątki będące obiektami klasy java.lang.Error sygnalizują poważne problemy i prowadzą do natychmiastowego zakończenia wykonywania programu. Zwykle reprezentowane przez te wyjątki błędy krytyczne dotyczą środowiska uruchomieniowego programu, większość błędów ma charakter nieprzewidywalny.
Przykłady błędów krytycznych:
- java.lang.InternalError – sygnalizuje błąd wewnętrzny wirtualnej maszyny Java,
- java.lang.VirtualMachineError – sygnalizuje brak zasobów uniemożliwiający dalszą pracę wirtualnej maszyny,
- java.lang.StackOverflowError – sygnalizuje błąd wynikający z przepełnienia stosu,
- java.lang.OutOfMemoryError – sygnalizuje brak dostępnej pamięci, której przydział jest wymagany np. nowo tworzonego obiektu.

### Klasyfikacja wyjątków
Wyjątki będące obiektami klasy java.lang.Exception są generowane w określonych warunkach i można wskazać instrukcję w kodzie programu, której wykonanie spowodowało zgłoszenie wyjątku. Wystąpienie wyjątku klasy rozszerzającej klasę java.lang.Exception jest zwykle możliwe do przewidzenia, wyjątkiem jest klasa potomna java.lang.RuntimeException, ponieważ obiekty tej klasy oraz wszystkich klas, które ją rozszerzają reprezentują wyjątki wykonawcze, których źródłem jest maszyna wirtualna, jednakże nie należą one do grupy błędów krytycznych.
W specyfikacji języka Java wyjątki typu java.lang.Error i java.lang.RuntimeException są klasyfikowane jako wyjątki niekontrolowane (unchecked), pozostałe typy wyjątków nazywamy kontrolowanymi (lub weryfikowalnymi).
Dla wszystkich wyjątków kontrolowanych kompilator weryfikuje czy w kodzie spełniono zasady ich propagacji, przechwytywania i obsługi.

### Przykłady wyjątków wykonawczych (runtime)
java.lang.ArithmeticException – zgłaszany w sytuacji wykonania dzielenia przez zero,
java.lang.ArrayIndexOutOfBoundsException – zgłaszany przy próbie odwołania się do nieistniejącego elementu tablicy,
java.lang.ClassCastException – zgłaszany przy próbie rzutowania obiektu na klasę, której obiekt nie jest instancją,
java.lang.IllegalArgumentException – zgłaszany w sytuacji przekazania do metody niedozwolonego lub nieodpowiedniego argumentu,
java.lang.UnsupportedOperationException – zgłaszany w sytuacji braku implementacji lub nieobsługiwanej operacji,
java.lang.NullPointerException – zgłaszany przy próbie odwołania się do nieistniejącego obiektu - wartość null

### Reguła obsłuż lub deklaruj
Zgodnie z regułą obsłuż lub deklaruj dla każdego wyjątku kontrolowanego/weryfikowalnego, który może być zgłoszony wewnątrz metody lub konstruktora należy:
- zadeklarować wyjątki jakie metoda lub konstruktor może zgłaszać z wykorzystaniem słowa kluczowego throws, wówczas każdy wyjątek będzie mógł być propagowany względem otaczania dynamicznego w poszukiwaniu odpowiedniego segmentu obsługi,
- zapewnić w metodzie lub konstruktorze lokalny segment obsługi wyjątku weryfikowalnego.

Należy zauważyć, ze wymienione podejścia można łączyć, ponieważ w lokalnym segmencie obsługi wyjątku można ponowie zgłosić obsługiwany wyjątek i wówczas będzie on propagowany.
Dodatkowo w ramach lokalnego segmentu obsługi wyjątków można zgłosić inny wyjątek, podając obsługiwany wyjątek jako przyczynę. Technika ta jest nazywana przepakowaniem lub opakowaniem wyjątku.

### Propagacja wyjątku
W języku programowania Java każdy zgłoszony nieobsłużony wyjątek jest zawsze propagowany zgodnie z kolejnością wywołań metod względem otaczania dynamicznego bloków kodu w poszukiwaniu najbliższego względem lokalizacji zgłoszenia i odpowiedniego segmentu obsługi wyjątku.
Propagacja wyjątku z metody lub konstruktora powoduje niejawne jego zgłoszenie w miejscu wywołania metody lub konstruktora. W przypadku propagacji wyjątku kontrolowanego wymagane jest jawne deklarowanie wyjątku przez każdy konstruktor lub metodę, która przekazuje wyjątek do bloku kodu, z którego została wywołana.
Segment obsługi jest odpowiedni dla wyjątku, gdy wyjątek jest typu zgodnego z wymienionym w segmencie obsługi wyjątku (względem operatora instanceof).
Poszukiwanie przez propagujący wyjątek najbliższego odpowiedniego segmentu obsługi wyjątku powoduje zakończenie przetwarzania dalszych instrukcji we wszystkich statycznie zagnieżdżonych blokach (tzw. otaczanie statyczne).

### Domyślna obsługa wyjątków
Wyjątek może być propagowany poza kod programu, wówczas zostaje przechwycony i obsłużony przez JVM, z zastosowaniem domyślnego segmentu obsługi wyjątków.
W przypadku propagacji wyjątku weryfikowalnego wymagane jest zamieszczenie go na liście deklarowanych wyjątków w definicji głównej statycznej metody (zwykle main());
Domyślna obsługa wyjątku przechwyconego przez JVM obejmuje:
- wypisanie listy wywołań metod względem kolejnych poziomów otaczania dynamicznego bloków instrukcji – odczytane z zawartości stosu z chwili utworzenia obiektu wyjątku.
- zakończenie działania programu z niezerową wartością zwracaną do systemu operacyjnego.

### Deklaracja wyjątków kontrolowanych dla metody
Definicja metody lub konstruktora może zwierać listę wyjątków, które mogą być propagowane.

```java
public void methodName(int value) throws java.io.IOException, CloneNotSupportedException {

//metoda może zawierać instrukcje, które

//mogą zgłosić wyjątek IOException oraz

//CloneNotSupportedException

throw new IOException();

}
```

Należy deklarować na liście wyjątków wszystkie wyjątki kontrolowane, które metoda lub konstruktor potencjalnie może zgłosić.
Można jawnie zgłaszać w definicji metody lub konstruktora wyjątki niekontrolowane (niezalecane).

### Lista deklarowanych wyjątków metody lub konstruktora
Lista deklarowanych wyjątków powinna być jak najbardziej precyzyjna, uogólnianie typów wyjątków nie jest zalecane.
Zalecane jest by lista deklarowanych wyjątków zawierała jedynie wyjątki weryfikowalne.
Metoda lub konstruktor z niepustą listę deklarowanych wyjątków nie musi zawierać żadnej instrukcji, której wykonanie spowoduje zgłoszenie wyjątku typu wymienionego na liście.
Wywołanie metody lub konstruktora posiadającego niepustą listę wyjątków wymaga zapewnienia dla każdego typu wyjątku weryfikowalnego/kontrolowanego wymienionego na liście lokalnego segmentu obsługi lub deklaracji na liście w bloku metody lub konstruktora, skąd nastąpiło wywołanie (reguła „obsłuż lub deklaruj”).

### Ogólna deklaracja wyjątków kontrolowanych dla metody
Określenie listy wyjątków w deklaracji metody oznacza, że potencjalnie metoda może zgłosić wyjątki będące obiektami wszystkich wymienionych na liście klas lub ich klas potomnych.
```java
public void importantMethod(String str) throws IOException {

//metoda może zawierać instrukcje, które

//mogą zgłosić wyjątek IOException oraz

//wyjatek każdej jej klasy potomnej np.

//EOFException lub FileNotFoundException

}
```
Alternatywnie zaprezentowano ogólniejszą listę deklarowanych wyjątków weryfikowalnych (niezalecane):
```java
public void importantMethod(String str) throws java.io.FileNotFoundException,

java.io.EOFException {

//metoda może ale nie musi zawierać instrukcji, które

//które mogą zgłosić EOFException lub FileNotFoundException

}
```

### Deklaracja wyjątków kontrolowanych dla metody przesłaniającej
Zadeklarowane wyjątki kontrolowane należą do sygnatury metody. Występuje więc konieczność zapewnienia zgodności definicji metod przesłanianych oraz narzuconych przez kontrakt interfejsu lub klasę abstrakcyjną.
Metoda przesłaniająca (@Override) nie może deklarować innych wyjątków kontrolowanych niż te, które są zadeklarowane w metodzie nadklasy, jednak może deklarować wyjątki jej podklas (bardziej szczegółowa lista deklarowanych wyjątków). Identyczne ograniczenie dotyczące listy deklarowanych wyjątków kontrolowanych metod implementowanych w wyniku spełnienia kontraktu interfejsu.
Jeżeli metoda w nadklasie nie deklaruje żadnych wyjątków kontrolowanych, wówczas przesłaniająca ją metoda w podklasie nie może deklarować żadnych wyjątków kontrolowanych.

### Deklaracja wyjątków kontrolowanych dla metody wymuszonej kontraktem interfejsu
Jeżeli kontrakt interfejsu implementowanego przez klasę wymaga metody, która posiada zadeklarowane wyjątki kontrolowane, wówczas definicja metody implementującej nie może zawierać zadeklarowanych bardziej ogólnych typów wyjątków.
```java
public interface SampleInterface {

public void sampleMethod(Integer val) throws

IOException;

…}
```
ponieważ EOFException i FileNotFoundException rozszerza klasę IOException, wówczas:
```java
public class ExampleClass implements SampleInterface {

public void sampleMethod(Integer val) throws

EOFException, FileNotFoundException {

…}

…}
```

### Segmenty obsługi wyjątków
Sekwencja bloków try-catch pozwala na zdefiniowanie segmentów obsługi dla typów wyjątków, które mogą zostać zgłoszone w trakcie wykonywania instrukcji w bloku try {}.
```java
try {

…

}

catch (EOFException eof){

…}

catch (IOException ioe){

…}

```
Jeżeli w bloku try zostanie zgłoszony wyjątek, wówczas zostanie on przechwycony i obsłużony poprzez wykonanie instrukcji zawartych w odpowiednim dla wyjątku segmencie obsługi catch. Po zakończeniu obsługi wyjątku (o ile w trakcie obsługi nie zgłoszono innego wyjątku) rozpoczyna się przetwarzanie pierwszej instrukcji zlokalizowanej tuż za blokami try-catch (lub try-catch-finally).

### Bloki: try-catch
W konstrukcji try-catch po pojedynczym bloku try może występować wiele bloków catch, z których każdy tworzy pojedynczy segment obsługi wyjątku. W sytuacji, gdy wiele segmentów obsługi będzie odpowiednich dla zgłoszonego w bloku try wyjątku, wówczas tylko jeden z nich może zostać użyty do jego przechwycenia i obsłużenia.
Kolejność zamieszczenia bloków catch po bloku try jest istotna ponieważ wybierany jest zawsze pierwszy segment obsługi dla wyjątku zgłoszonego w bloku try, którego typ przypisanego wyjątku jest zgodny z aktualnie zgłoszonym. Dlatego bloki catch muszą być ułożone w kodzie rozpoczynając od segmentów obsługi wyjątków najbardziej szczegółowych a kończąc na najbardziej ogólnych. Zachowanie odpowiedniej kolejności segmentów obsługi wyjątków wymusza kompilator.

### Segmenty obsługi wyjątków weryfikowalnych i nieweryfikowalnych
Sekwencja bloków try-catch nie gwarantuje, że każdy wyjątek zgłoszony wewnątrz bloku try zostanie przechwycony przez jeden z segmentów obsługi catch. Wymieniona sytuacja wystąpi jeżeli zgłoszony wyjątek nie będzie zgodny względem typu z żadnym segmentem obsługi wyjątków.
Wyjątki zgłoszone poza blokiem try nigdy nie będą przechwycone i obsłużone z zastosowaniem występujących bezpośrednio po bloku try segmentów obsługi wyjątków catch.
Utworzenie segmentu obsługi dla wyjątku weryfikowalnego wymaga występowania przynajmniej jednej instrukcji w bloku try, która deklaruje możliwość zgłoszenia tego wyjątku weryfikowalnego.

### Bloki: try-finally
Sekwencja bloków try-finally pozwala na zdefiniowanie grupy instrukcji w bloku finally, które niezależnie od zgłoszenia wyjątku w bloku try będą wykonane. Zgłoszenie wyjątku w bloku try przerywa przetwarzanie dalszych instrukcji z tego bloku (podobnie jak w try-catch).
W wyniku zastosowania propagacji zgłoszony nieobsłużony wyjątek zostanie wówczas przekazany do bloku zewnętrznego statycznie otaczającego blok try-finally.

```java
{
try {
…
} finally {
… //grupa instrukcji wykonywana niezależnie od
//wystąpienia zgłoszenia wyjątku w bloku try
}
…
}
```

### Bloki: try-catch-finally
Sekwencja bloków try-catch-finally pozwala na zdefiniowanie grupy instrukcji w bloku finally, które niezależnie od zgłoszenia wyjątku w bloku try i segmentu jego obsługi zawsze będą wykonane.
```java
try {

…

}catch (SomeException ex){

…

}catch (Exception ex){

…

}finally {

…

}
```
Bloki nie mogą być rozdzielone innymi instrukcjami. Struktury try-catch-finally można zagnieżdżać.

### Podział try-catch-finally na try-finally i try-catch
Zaleca się podział sekwencji bloków try-catch-finally na zagnieżdżone bloki try-finally oraz try-catch.
Oprócz bardziej czytelnego kodu programista zyskuje także możliwość obsługiwania wyjątków zgłaszanych w wyniku wykonania instrukcji zawartych w bloku finally.
```java
try {
try {
… //instrukcje programu
}
finally {
… //instrukcja zwolnienia przydzielonych zasobów
}
}
catch (IOException ioe){
…
}
catch (SomeException ex){
…
}
```

### Pominięcie propagacji wyjątku
Jeżeli w trakcie propagacji wyjątku wystąpi zgłoszenie innego wyjątku np. w sekcji finally, wówczas wyjątek zostanie pominięty (brak jego przechwycenia i obsługi) np.
```java
try {
try {
… //instrukcje programu
throw new IllegalArgumentException();
}
finally {
… //instrukcja zwolnienia przydzielonych zasobów
throw new IOException();
}
}
catch (IOException ioe){
…
}
catch (Exception ex){
…
}
```

### Blok try-with-resources
Od JDK w wersji 7 dostępna jest składania bloku try-with-resources pozwala na zainicjowanie w bloku try obiektów, których klasy implementują interfejs java.lang.Autoclosable. Po zakończeniu wykonania bloku try-with-resources, zostaną na zainicjowanych w nim obiektach wykonane operacje close() w kolejności odwrotnej do inicjowania obiektów w bloku try-with-resources.
Blok try-with-resources może występować samodzielnie, bez bloków catch oraz finally zlokalizowanych bezpośrednio za nim.
```java
try (Class1 res1 = new Class1(); Class2 res2 = new Class2()) {
...
}
```

### Odstępstwa od kompletnego przetwarzania bloku finally
Instrukcje zawarte w bloku finally nie będą wykonane kompletnie w następujących sytuacjach:
gdy działanie programu pracującego w wirtualnej maszynie Java zostanie jawnie zakończone wykonaniem System.exit(int) – zwrócenie wartości innej niż zero (tzw. kod błędu) do systemu operacyjnego ozn. niepoprawne zakończenie działania programu.
jeżeli jedna z instrukcji zawarta w bloku finally zgłosi wyjątek,
jeżeli w bloku finally zostanie wywołana instrukcja return,
gdy wystąpi uszkodzenie sprzętowe lub awaria środowiska (np. systemu operacyjnego lub wirtualnej maszyny itp.)
Zawartość bloku finally zostanie wykonana także w sytuacji, gdy wewnątrz poprzedzającego bloku try zostanie wykonana instrukcja return.

### Problem „połykania” wyjątków
Nigdy nie należy zamieszczać w kodzie pustego segmentu jego obsługi – jest to tzw. problem „połykania” wyjątków.
Nawet chwilowe zastosowanie pustego segmentu obsługi wyjątków może doprowadzić do zignorowania sytuacji wystąpienia wyjątku, przez co późniejsze wykrycie błędów występujących w programie będzie utrudnione.
```java
try {
//miejsce zgłoszenia wyjątku
instrukcja_zgłaszająca_wyjatek();
}
catch (Exception ex){
}
/*brak instrukcji w powyższym segmencie obsługi wyjątków powoduje ukrywanie wystąpienia każdego wyjątku, którego klasa rozszerza Exception. */
```

### Opakowanie/przepakowanie wyjątku
W segmencie obsługi wyjątku można utworzyć nowy wyjątek, podając jako przyczynę jego zgłoszenia przechwycony wyjątek.
Stosując technikę opakowania wyjątków można budować łańcuchy wyjątków, które są stosowane w celu ujednolicenia typu zgłaszanych w programie wyjątków (np. zamiana wyjątku niekontrolowanego na kontrolowany).
```java
try {
//instrukcje zapewniajace wykonanie operacji SQL w bazie danych
...
}
catch (SQLException dbex){
Throwable se = new ServletException(”Błąd w bazie danych”);
se.initCause(dbex);
throw se;
}
```

### Segment obsługi różnych wyjątków
W wersji 7 Javy zapewniono możliwość tworzenia segmentu obsługi dla wielu różnych typów wyjątków wyjątków (multi-catch), co pozwoliło programistom efektywniej tworzyć czytelniejszy kod unikając duplikatów bloków instrukcji.
Zgłoszony wewnątrz bloku try wyjątek zostanie przechwycony, jeżeli tylko jego typ jest:
- elementem zbioru typów wymienionych wyjątków wymienionych w segmencie obsługi,
- podklasą jednego z wymienionych w segmencie obsługi dla wielu typu wyjątków.
```java
try {
…
}
catch (SomeException | OtherException exception) {
…
}
```

### 
Zasady stosowania segmentu obsługi różnych wyjątków
Stosowanie segmentu obsługi dla wielu typów wyjątków wymaga zastosowania następujących zasad:
nie należy jednocześnie wyszczególniać nadklas i podklas w liście typów wyjątków segmentu multi-catch,
parametr segmentu obsługi wyjątków jest zawsze niezmienny (final),
W wersji 7 języka programowania Java wprowadzono także konstrukcję: try-with-resources (blok try może wówczas występować bez bloków catch i finally)
```java
try {
…
}
catch (SomeException | OtherException exception) {
//exception = new Exception(); jest niepoprawne
…
}
```

### Zasada generuj wcześnie wyjątek i przechwytuj późno
W sytuacji propagacji zgłoszonego/wygenerowanego wyjątku zarówno kontrolowanego jak i niekontrolowanego zawsze poszukiwany jest najbliższy odpowiedni segment obsługi wyjątku.
Dopasowanie wyjątku do segmentu powoduje jego przechwycenie, wówczas wykonywane są instrukcje zawarte w segmencie obsługi wyjątku. Wczesne zgłoszenie wyjątku przerywa wykonywanie aktualnego bloku instrukcji, dlatego w sytuacji wystąpienia błędu kolejne instrukcje występujące w bloku nie zostaną wykonane.
Nie należy zakładać, że miejsce zgłoszenia wyjątku oraz segment jego obsługi będą zawsze występowały w tym samym bloku instrukcji. Często przechwytuje się wyjątek w metodzie wyższego poziomu względem otaczania dynamicznego, gdzie instrukcje występujące w segmencie obsługi mogą być wykonane (np. wszystkie niezbędne informacje są dostępne) lub można zapewnić ujednoliconą obsługę wyjątku zgłaszanego w wielu różnych lokalizacjach w kodzie.

### Przedstawienie wywołań metod ze stosu
Dane z zawartością stosu (stack trace) zawierają listę wszystkich niezakończonych wywołanych metod/konstruktorów z chwili utworzenia obiektu wyjątku. Informacje te są pomocne w diagnostyce rzeczywistych przyczyn zgłoszenia wyjątku (dodatkowo udostępniana jest lokalizacja każdej otwartej metody w kodzie źródłowym). Nie należy utożsamiać zawartości stosu z kolejnością propagacji wyjątku pomiędzy blokami kodu w ramach poziomów wyznaczonych przez dynamiczne otaczanie bloków instrukcji.
Zawartość stosu z chwili utworzenia wyjątku jest niezależna od miejsca jego zgłoszenia, przechwycenia i obsłużenia wyjątku.
Jeżeli wyjątek posiada ustaloną przyczynę (cause), którą jest inny wyjątek wówczas metoda Thorowable.printStackTrace() pozwala na wyświetlenie zawartości stosu dla każdego z wyjątków, które są połączone zależnością przyczynową.

### Przykładowa zawartość stosu
Przykład wyświetlenia zawartości stosu z chwili utworzenia wyjątku kontrolowanego/weryfikowalnego ErrorException (klasa bezpośrednio rozszerzająca java.lang.Exception) z wykorzystaniem metody Throwable.printStackTrace():
Poszczególne wpisy wskazują instrukcje w kodzie źródłowym, które stworzyły kolejne poziomy otaczania dynamicznego dla utworzonego wyjątku. Prezentowana zawartość stosu nie jest czytelna dla użytkownika oprogramowania i nigdy nie powinna być udostępniana użytkownikowi finalnej wersji oprogramowania. Zawartość stosu należy wykorzystywać wyłącznie do diagnostyki problemów/błędów reprezentowanych przez zgłoszony wyjątek.
```java
pl.lodz.p.it.ssbd.exception.ErrorException: Komunikat błędu at pl.lodz.p.it.ssbd.SecondUtility.callWithCheckedException(SecondUtility.java:13) at pl.lodz.p.it.ssbd.FirstUtility.otherWithCheckedException(FirstUtility.java:14) at pl.lodz.p.it.ssbd.FirstUtility.callWithCheckedException(FirstUtility.java:19)

at pl.lodz.p.it.ssbd.ApplicationWithExceptions.main(ApplicationWithExceptions.java:18)
```

### Analiza wywołań metod ze stosu w trakcie wykonania programu
Od Java SE 1.4 oprócz wypisania zawartości stosu z chwili utworzenia wyjątku istnieje też możliwość analizy poszczególnych jego elementów:
```java
Throwable throwable = new Throwable();
StackTraceElement[] stackTraceTab = throwable.getStackTrace();
for (StackTraceElement element: stackTraceTab) {
//analiza poszczególnych elementów ze stosu
System.out.println(”Element stosu zawiera metodę: ” +
element.getClassName() + element.getMethodName() +
” z pliku źródłowego ” +
element.getFileName() + element.getLineNumber());
…
}
```

### Ogólny segment obsługi wyjątków
W celu uniknięcia propagacji wyjątków do wirtualnej maszyny Java w nadrzędnym bloku kodu należy stosować ogólny segment obsługi wyjątków:
```java
public static void main(String args[]) {
try {
//instrukcje zależne od funkcjonalności programu
}
catch (Throwable exception) {
/*ogólny segment może zosać dopasowany do
dowolnego typu wyjątku */
System.err.println(”Wystąpił błąd,”
+” program zakończył działanie”);
/*inne działania w ramach obsługi dla zgłoszonego w bloku try wyjątku (np. zapis informacji o zaistniałym błędzie w dzienniku zdarzeń) */
System.exit(6);
/*zakończenie programu z wartością inną niż zero
sygnalizuje do systemu operacyjnego niepoprawne
} zakończenie programu (np. wystąpienie błędu) */
} //nie należy zamieszczać bloku finally po catch ogólnym segmencie obsługi wyjątków
```

### Wskazówki stosowania wyjątków
W kodzie każdego programu zawsze należy uwzględnić możliwość wystąpienia wyjątków, w szczególności wyjątków niekontrolowanych.
Należy wykorzystywać hierarchię wyjątków wyszukując odpowiednią, istniejącą podklasę wyjątku lub stworzyć własną, w szczególności dotyczy to wyjątków określonych w segmentach obsługi. Zawsze precyzyjnie należy dobierać typ obiektów wyjątków dla każdej z sytuacji błędu.
Dla wyjątków weryfikowalnych/kontrolowanych stosuj zasadę: obsłuż lub deklaruj (dot. metod i konstruktorów) oraz nie poszerzaj listy wyjątków deklarowanych w metodzie przesłaniającej lub wymuszonej kontraktem interfejsu.
Kolejność segmentów obsługi wyjątków w try-catch jest istotna, a segmenty obsługi wyjątków weryfikowalnych wymagają obecności przynajmniej jednej instrukcji w bloku try, która może zgłosić taki wyjątek.
Stosuj też zasadę: generuj wcześnie wyjątek i przechwytuj późno. Nigdy nie należy „połykać” wyjątków.
Minimalna obsługa wyjątku powinna zapewniać przedstawienie użytkownikowi czytelnego komunikatu (nie stack trace) informującego o błędzie (w szczególności istotne by poinformować o zakończeniu przetwarzania). W sytuacji braku możliwości wybrnięcia z błędu należy przy zakończeniu programu zgłosić niezerowy kod błędu.

### Asercje w języku programowania Java
Asercje są techniką programowania zachowawczego, pozwalającą ustalić warunki poprawności (predykaty) dla wykonania programu. Zapis asercji w języku programowania Java (dostępne od Java SE 1.4):
assert warunek;
assert warunek : wyrażenie;
W trakcie wykonania programu jeżeli warunek nie jest spełniony (wartość false w wyniku jego wartościowania) wówczas niejawnie zgłaszany jest wyjątek: java.lang.AssertionError
Jeżeli w asercji określono wyrażenie, to jest ono wykorzystywane do utworzenia łańcucha znaków jako wartości komunikatu załączonego do zgłoszonego błędu java.lang.AssertionError


### Obsługa asercji w języku programowania Java
Standardowe ustawienia JVM wyłączają wartościowanie warunków zamieszczonych w kodzie asercji, wówczas wyjątki java.lang.AssertionError nie są zgłaszane.
Włączenie wartościowania warunków zamieszczonych w kodzie asercji nie wymaga ponownej kompilacji kodu programu, ponieważ odpowiada za tą funkcjonalność moduł JVM ładujący klasy (class loader). Kod asercji jest usuwany przez moduł ładujący klasy, dlatego wyłączenie asercji nie spowalnia programu.
Asercje nie muszą być usuwane z kodu źródłowego finalnej wersji programu.

### Włączenie/wyłączenie asercji w języku programowania Java
Włączenie obsługi asercji:
java –-enableassertions OtherApplication
lub
java -ea OtherApplication
Istnieje także możliwość włączenia asercji dla pakietu wraz z wszystkimi jego podpakietami.
java -ea:pl.lodz.p.it.ssbd.sub... SampleApplication
Wyłącznie asercji jedynie dla wybranego pakietu wraz z wszystkimi jego podpakietami:
java -ea -da:pl.lodz.p.it.ssbd.sub... SameApplication

### Asercje w języku programowania Java a testy jednostkowe
Dostępne w języku programowania Java asercje są stosowane wyłącznie w fazie rozwoju i testów oprogramowania, stanowią więc podobny, jednakże znacznie prostszy mechanizm w porównaniu z testami jednostkowymi.
Asercje nie wykluczają stosowania testów jednostkowych, ponieważ pozwalają sprawdzać warunki logiczne bez konieczności tworzenia przypadków testowych. Zdefiniowane asercje są praktycznie nierozłączne od kodu źródłowego programu ułatwiając późniejszą diagnostykę np. gdy konieczne jest wykrycie błędu odkrytego w finalnej wersji oprogramowania.
Asercje są także przydatne w przypadku wystąpienia awarii. Można stosować asercje do dokumentowania przyjętych założeń tzw. warunków wstępnych (precondition).

## 8. Wykład - wyjatki aplikacyjne i systemowe

### Spis zagadnień
Klasyfikacja: wyjątki biznesowe/aplikacyjne i systemowe
Standardowa obsługa wyjątków realizowana przez kontener
Wpływ wyjątków na zakończenie bieżącej transakcji aplikacyjnej
Różnice pomiędzy wyjątkiem systemowym a aplikacyjnym
Sytuacje zgłaszania wyjątków aplikacyjnych oraz niezbędny zbiór informacji przekazywanych przez zgłoszone wyjątki
Lokalizacja segmentów i obsługa wyjątków zgłoszonych w warstwie logiki
Przepakowanie wyjątków zgłoszonych przez DBMS
Powiązanie stron błędów z kodami HTTP
Wyświetlanie informacji o wystąpieniu błędu w interfejsie użytkownika dostarczanym poprzez dynamicznie generowane strony WWW

### Scenariusze błędów w przypadkach użycia
Funkcjonalność aplikacji biznesowej jest uzależniona od zaimplementowanych przypadków użycia. W trakcie wykonania przypadku użycia mogą występować błędy, kod aplikacji powinien zapewniać obsługę tych błędów.
Implementacja każdego przypadku użycia w aplikacji biznesowej obejmuje zarówno scenariusz pozytywny oraz wiele scenariuszy błędów. Każdy ze scenariuszy błędów uwzględnia reakcję oprogramowania na wystąpienie innej sytuacji błędu w trakcie realizacji przypadku użycia.
Implementacja scenariusza błędu powinna uwzględnić:
- zarejestrowanie sytuacji błędu w dzienniku zdarzeń (zgodnie z zasadą nie ignorujemy błędów)
- podjęcie działań umożliwiających wybrnięcie z błędu i kontynuowanie przetwarzania w ramach przypadku użycia
- poinformowanie użytkownika, który zainicjował akcję (wykonanie przypadku użycia) o zaistniałym błędzie.

### Zaawansowana obsługa błędów w systemach informatycznych
Nie każdy błąd umożliwia zastosowanie procedury wybrnięcia z błędu, nie każde wybrnięcie z błędu jest skuteczne dla użytkownika oprogramowania, który aktywował akcję.
Obsługa błędów może uwzględniać:
- Generowanie automatycznych kodów błędów identyfikujących wystąpienie problemu,
- Przygotowanie raportów z opisem błędu, który zawiera informacje diagnostyczne pomocne przy wykrywaniu przyczyn wystąpienia błędu,
- Automatyczne zgłaszanie błędów do producenta oprogramowania,
- Przekierowanie użytkownika do innego narzędzia rejestracji błędów (m.in. BugTrucker , Bugzilla, Redmine), gdzie użytkownik może opisać zaistniałą sytuację błędu wypełniając formularz zgłoszenia.

### Lokalizacja zgłoszeń i obsługi wyjątków
W wielowarstwowych aplikacjach biznesowych miejsce zgłoszenia błędu wyjątku jest odmienne od lokalizacji segmentu obsługi, często lokalizacje te należą do różnych warstw oprogramowania.
Bez ponownego zgłaszania wyjątku ani przepakowania w inny wyjątek można wyróżnić następujące przypadki:
- Zgłoszenie wyjątku w warstwie logiki biznesowej, przechwycenie i obsługa zgłoszonego wyjątku w warstwie logiki biznesowej. Stosowane w sytuacji realizacji wybrnięcia z błędu poprzez działania korygujące mające na celu eliminację naruszeń reguł biznesowych przetwarzania danych.
- Zgłoszenie wyjątku w warstwie logiki biznesowej, propagacja wyjątku do warstwy prezentacji, gdzie wyjątek jest przechwytywany i obsługiwany. Umożliwia wyświetlenie stosowanego komunikatu o zaistniałym błędzie w interfejsie użytkownika.
- Zgłoszenie wyjątku w warstwie prezentacji (np. w widoku Web) i jego przechwycenie i obsługa w ramach tej samej warstwy.

### Błędy przetwarzania w biznesowych systemach informatycznych JEE
Biznesowy system informatyczny musi zapewniać realizację zgodnie ze specyfikacją funkcjonalną (zgodnie z regułami logiki biznesowej), gdzie należy uwzględnić sytuacje wystąpienia błędu w trakcie przetwarzania danych. W języku programowania Java wystąpienie błędu w trakcie przetwarzania kodu uruchomionego programu jest zgłaszane poprzez wystąpienie wyjątku. W każdym przypadku użycia należy rozważyć oprócz bezbłędnych scenariuszy głównych scenariusze uwzględniające błędy.
W przypadku zastosowania kontenera i komponentów (np. ziarnach EJB) do zapisu reguł logiki dla procesów biznesowych realizowanych w biznesowych systemach informatycznych JEE wyróżnia się podział na wyjątki:
- systemowe – zgłaszane przez kontener w sytuacji, gdy przetwarzanie danych w ramach logiki biznesowej nie może być realizowane,
- biznesowe/aplikacyjne – zgłaszane przez komponenty w odpowiedzi na błąd logiki biznesowej w trakcie przetwarzania danych (wymagane dedykowanego oznaczenia klasy wyjątku aplikacyjnego lub klasy bazowej).
Przyczyną zgłoszenia wyjątku systemowego jak  i  aplikacyjnego może być zgłoszenie wyjątku.

### Propagacja wyjątku w architekturze kontener-komponent
Brak przechwycenia i obsługi zgłoszonego nieprzechwyconego wyjątku w metodach biznesowych komponentów EJB powoduje, że trafia on do kontenera EJB, który wówczas zajmuje się jego obsługą. W ramach obsługi kontener przepakowuje zgłoszony wyjątek nieaplikacyjny w wyjątek systemowy, opakowywany wyjątek jest ustawiany jako przyczyna (initCause()) wyjątku systemowego.
Kontener EJB pośredniczy pomiędzy wywołaniami metod biznesowych różnych komponentów, zatem zgłoszone wyjątki nieaplikacyjne wewnątrz metody biznesowej są propagowane do kontenera, który je przechwytuje i obsługuje  z zastosowaniem domyślnej procedury obsługi.

### Wyjątki systemowe
Klasy wyjątków systemowych, które mogą być zgłaszane przez kontener EJB:
- nieweryfikowalne wyjątki java.lang.RuntimeException wraz z podklasami, w szczególności należy wyróżnić podklasę jakarta.ejb.EJBException.
- weryfikowalne wyjątki java.rmi.RemoteException wraz z podklasami.
Sytuacje zgłoszenia wyjątku systemowego przez kontener EJB:
- brak możliwości wywołania metody biznesowej komponentu EJB, np. niespełnione reguły autoryzacji lub niespełnione wymagania dotyczące przetwarzania transakcyjnego z wykorzystaniem zarządzania transakcją przez kontener CMT. W sytuacji braku możliwości wywołania metody biznesowej nie jest stosowana domyślna procedura obsługi wyjątku.
- zgłoszenie w trakcie przetwarzania metody biznesowej komponentu EJB nieweryfikowalnego i nieaplikacyjnego wyjątku.
Kontener EJB zwykle nie przechwytuje wyjątków aplikacyjnych.

### Standardowa obsługa wyjątków przez kontener
W sytuacji propagacji wyjątku nieaplikacyjnego z metody biznesowej komponentu EJB do kontenera, wówczas kontener EJB stosuje domyślną procedurę obsługi, która obejmuje:
- Automatyczne odwołanie (rollback) bieżącej transakcji aplikacyjnej, w granicach której była wykonywana metoda biznesowa zgłaszająca wyjątek nieaplikacyjny,
- Zapis w dzienniku zdarzeń komunikatu o sytuacji zgłoszenia wyjątku, komunikat oprócz klasy wyjątku zawiera także zawartość stosu z chwili jego powstania,
- Usunięcie instancji komponentu EJB, którego metoda biznesowa zgłosiła wyjątek nieaplikacyjny, ponieważ kontener zakłada uszkodzenie (błędny stan) i niestabilność działania takiego komponentu EJB. Po usunięciu komponentu EJB powoływana jest nowa instancja tej samej klasy komponentu.
- Zgłoszenie wyjątku systemowego, którego typ jest zależny od sposobu wywołania metody biznesowej m. in.: java.rmi.RemoteException, jakarta.ejb.EJBException, jakarta.ejb.EJBTransactionRollbackException.
Zgłoszony wyjątek systemowy będzie opakowywał nieaplikacyjny wyjątek, jaki został przechwycony przez kontener EJB.

### Wpływ usuwania komponentu EJB na klienta
Wpływ usuwania przez kontener komponentu EJB, do którego należała metoda biznesowa, która zgłosiła wyjątek nieaplikacyjny zależy od typu usuniętego komponentu. Realizowane w ramach standardowej procedury obsługi wyjątku usunięcie:
- bezstanowego komponentu sesyjnego (@Stateless) nie jest zauważalne dla oprogramowania klienta,
- stanowego komponentu sesyjnego (@Stateful) powoduje utratę stanu konwersacyjnego, a kolejne odwołania klienta do instancji komponentu EJB stają się nieprawidłowe, zostanie wówczas zwrócony wyjątek systemowy jakarta.ejb.NoSuchEJBException.
- sterowanego komunikatami (@MessageDriven), wówczas nie ma gwarancji dostarczenia aktualnie wysyłanego komunikatu w ramach JMS (Java Message Service).

### Typy najistotniejszych, zgłaszanych przez kontener EJB wyjątków systemowych
- jakarta.ejb.EJBAccessException – wyjątek systemowy zgłaszany przez kontener, jeżeli klient wywołujący metodę biznesową nie spełnił reguł autoryzacji (np. tożsamość klienta nie posiada wymaganej przez metodę biznesową roli).
- jakarta.ejb.EJBException – najbardziej ogólny wyjątek systemowy zgłaszany, jeżeli klient nie propagował transakcji do wywołanej metody biznesowej komponentu EJB, w ramach wykonania której został zgłoszony wyjątek nieaplikacyjny lub kiedy klient wywołał metodę z atrybutem transakcyjnym TransactionAttributeType.NEVER,
- jakarta.ejb.EJBTransactionRequiredException – wyjątek systemowy zgłaszany, jeżeli klient nie posiadał kontekstu transakcji, który był wymagany przez metodę biznesową (atrybut transakcyjny TransactionAttributeType.MANDATORY),
- jakarta.ejb.EJBTransactionRollbackException – wyjątek systemowy zgłaszany, jeżeli klient propagował odwołaną transakcję do wywoływanej metody biznesowej komponentu EJB.
- jakarta.ejb.NoSuchEJBExeption – wyjątek opisany slajd wcześniej.

### Różnice pomiędzy wyjątkiem aplikacyjnym i systemowym
Wyjątki systemowe są zgłaszane przez kontener EJB w sytuacji, gdy kod komponentów biznesowych nie zawiera obsługi problemu/błędu. Kontener zapewnia ograniczoną i ogólną obsługę wyjątków nieaplikacyjnych np. stosuje domyślną procedurę obsługi zgłoszonego błędu.
Wyjątki systemowe mogą wystąpić w trakcie wykonania dowolnej akcji, natomiast wyjątek aplikacyjny może zostać zgłoszony jedynie w ograniczonej liczbie akcji. Segment obsługi wyjątku aplikacyjnego nie jest powiązany z wszystkimi akcjami.
Celem zgłoszenia wyjątku aplikacyjnego jest wykluczenie kontenera EJB z jego obsługi (kontener ignoruje wyjątki aplikacyjne). Wyjątek aplikacyjny może zatem propagować bez udziału kontenera pomiędzy metodami biznesowymi komponentów EJB, także do warstwy prezentacji (np. w celu wyświetlenia szczegółowego komunikatu o problemie występującym w trakcie przetwarzania).
Wyjątki aplikacyjne dają możliwość podjęcia działań korygujących do zaistniałego problemu (tzw. wybrnięcie z błędu) bez potrzeby odwołania bieżącej transakcji. Ewentualnie możliwe jest również wybrnięcie z błędu poprzez ponowienie odwołanej transakcji aplikacyjnej.

### Wyjątki aplikacyjne
Klasa wyjątku aplikacyjnego musi zostać odpowiednio oznaczona, by w wyniku propagacji takiego wyjątku kontener nie stosował standardowej procedury obsługi wyjątku. Dostępne możliwości oznaczenia klasy wyjątku jako wyjątek aplikacyjny z wykorzystaniem:
- adnotacji jakarta.ejb.AppliactionException zamieszczonej w kodzie źródłowym przed definicją klasy wyjątku,
- wpisu w pliku ejb-jar.xml zawierającego deskryptor XML konfiguracji komponentów EJB.

### Wyjątki aplikacyjne w aplikacji REST
W przypadku zastosowania REST (REpresentational State Transfer) klasa bazowa wyjątku aplikacyjnego powinna rozszerzać klasę jakarta.ws.rs.WebAppliactionException.
Wówczas wszystkie wyjątki aplikacyjne mogą być odwzorowywane na odpowiedni kod błędu usługi sieciowej (wartość status decyduje o kodzie zwróconym przez Web Service) oraz nie muszą być zamieszczane w listach deklarowanych wyjątków metod biznesowych (wyjątki typu jakarta.ws.rs.WebAppliactionException są wyjątkami wykonywawczymi). Alternatywne rozwiązanie przy wykorzystaniu REST: jeżeli klasa bazowa wyjątków aplikacyjnych nie rozszerza klasy jakarta.ws.rs.WebAppliactionException to w przypadku obsługi żądań usługi REST należy zastosować opakowanie wyjątków aplikacyjnych w wyjątek klasy jakarta.ws.rs.WebAppliactionException.
```java
@ApplicationException(rollback=true)
public class AppBaseException
extends WebApplicationException {
...
}
```


### Opakowanie wyjątków systemowych w aplikacji REST
Zastosowanie usług sieciowych REST (REpresentational State Transfer) pozwala zgłaszać komunikaty błędu, co dla wyjątków systemowych zgłaszanych przez kontener EJB wymaga wcześniejszego zapakowania ich w wyjątek typu jakarta.ws.rs.WebAppliactionException. Przykład implementacji z zastosowaniem interfejsu jakarta.ws.rs.ExceptionMapper:
```java
@Provider
public class SystemExceptionMapper implements ExceptionMapper<Throwable> {
@Override
public Response toResponse(final Throwable throwable) {
try {
throw throwable;
} catch (WebApplicationException wae) {
return wae.getResponse();
} catch (EJBAccessException | AccessLocalException ae) {
return AppBaseException.createForAccessDeny(ae).getResponse();
} catch (Throwable te) {
Return AppBaseException.createForGeneralError(te).getResponse();
}
}
}
```

### Cechy wyjątków aplikacyjnych
Zarówno wyjątek weryfikowalny jak i nieweryfikowalny może być wyjątkiem aplikacyjnym. Wyjątki weryfikowalne jakie mogą być zgłaszane w metodach biznesowych komponentów EJB powinny zostać oznaczone jako aplikacyjne lub powinny rozszerzać klasę wyjątku aplikacyjnego.
Brak wymienienia weryfikowalnego wyjątku aplikacyjnego w sygnaturze metody biznesowej (throws) wywołującą inną metodę biznesową, która może zgłosić wyjątek weryfikowalny powoduje zastosowanie przez kontener domyślnej procedury obsługi wyjątku, mimo oznaczenia wyjątku jako aplikacyjny.
Stosując atrybut rollback przy oznaczeniu klasy wyjątku aplikacyjnego można określić wpływ wystąpienia wyjątku aplikacyjnego na odwołanie bieżącej transakcji. Domyślna wartość tego atrybutu określa, że bieżąca transakcja nie zostanie odwołana w sytuacji wystąpienia wyjątku aplikacyjnego.
Klasa rozszerzająca klasę wyjątku aplikacyjnego też jest wyjątkiem aplikacyjnym, obowiązują także ustawienia atrybutu rollback nadane dla klasy nadrzędnej wyjątku aplikacyjnego.

###  Strategie obsługi wyjątku zgłoszonego w metodzie biznesowej komponentu EJB
Zgłoszony w trakcie przetwarzania metody biznesowej komponentu EJB wyjątek może być:
przechwycony i obsłużony przez lokalnie zamieszony w metodzie biznesowej segment obsługi wyjątków. Jeżeli w ramach obsługi wyjątek nie będzie ponownie zgłaszany lub nie zrealizowano zgłoszenia innego wyjątku, wówczas nie występuje konieczność tworzenia wyjątku aplikacyjnego ani systemowego.
propagowany z metody biznesowej, wówczas istotne jest rozróżnienie czy typ propagowanego obiektu wyjątku został oznaczony jako wyjątek aplikacyjny. Jeżeli typ propagowanego wyjątku (możliwe również poprzez oznaczenie nadklasy) był oznaczony jako aplikacyjny, wówczas kontener EJB wyjątku aplikacyjnego nie przechwyci i nie zapewni jego obsługi z wykorzystaniem domyślnej procedury obsługi (w ramach której zawsze następuje zgłoszenie wyjątku systemowego). Przypadek ten dotyczy także wyjątków propagowanych w wyniku ponownego zgłoszenia lub zgłoszenia innego wyjątku w segmencie obsługi wyjątku zlokalizowanym w metodzie biznesowej.

### Przykłady sytuacji zgłoszenia wyjątków aplikacyjnych
Wyjątki aplikacyjne powinny być zgłaszane w sytuacjach naruszenia ograniczeń biznesowych (ustalone reguły przetwarzania i przechowywania danych), wśród których można wyróżnić m. in.:
Próba naruszenia reguł przechowywania danych np. naruszenie ograniczeń struktur relacyjnej bazy danych przy próbie zmiany przechowywanych w niej danych, komunikat zgłoszonego wyjątku zawiera identyfikację ograniczenia bazodanowego, które zostało naruszone.
Próba naruszenia ograniczeń związanych z relacjami pomiędzy obiektami przechowującymi dane np. próba nawiązania już istniejącej relacji pomiędzy obiektami encji, próba usunięcia nie istniejącej relacji,
Próba przetwarzania bez wszystkich wymaganych parametrów lub w sytuacji niepoprawnego stanu danych np. wywołanie metody z argumentem o wartości null.
Próba zatwierdzenia transakcji, w trakcie realizacji której nastąpiła równoległa zmiana danych np. mechanizm blokad optymistycznych.


### Przechwytywanie wyjątków zgłoszonych przez DBMS
Wszystkie błędy związane z realizacją kwerend SQL w relacyjnej bazie danych są zgłaszane jako wyjątki, kiedy tylko zarządca encji EntityManager z wykorzystaniem jednostki utrwalania zleci ich wykonanie. Zwykle wykonanie kwerend SQL jest realizowane przez zarządcę encji tuż przed zakończeniem bieżącej transakcji. W przypadku transakcji zarządzanej przez kontener CMT zwykle oznacza to zgłoszenie wyjątków wraz z zakończeniem metody biznesowej komponentu dostępowego np. (metody Endpoint EJB), przez co brak możliwości przechwycenia i obsługi zgłoszonych wyjątków w ramach segmentu obsługi wyjątków zlokalizowanego w metodzie biznesowej.
Przechwycenie wyjątków związanych z błędami jakie zgłosił DBMS w trakcie realizacji kwerend SQL wymaga zatem wcześniejszego wymuszenia wykonania kwerend w bazie danych jeszcze przed zakończeniem bieżącej transakcji aplikacyjnej.
Wymuszenie wykonania kwerend w bazie danych zapewnia metoda EntityManager.flush()

### Zgłoszenie wyjątku aplikacyjnego w fasadzie dla Encji
Typy wyjątków zgłaszanych przez relacyjną bazę danych związane z naruszeniem ograniczeń nałożonych na dane różnią się w zależności od wykorzystywanego DBMS (brak standardów JDBC dla typów zgłaszanych wyjątków). Identyfikację ograniczenia bazodanowego jakie zostało naruszone można zwykle uzyskać poprzez analizę komunikatu wyjątku zgłoszonego przez DBMS.
Wykonanie kwerend SQL może zwrócić wyjątek jakarta.persistence.OptimisticLockException, związany z zastosowanie systemu blokad optymistycznych. W szczególności dotyczy to metod biznesowych komponentów EJB, które powodują zmianę lub usunięcie encji w stanie zarządzanym (przynależność do bieżącej transakcji). Należy pamiętać, że zmianę stanu encji niezarządzanej zapewnia metoda EntityManager.merge()
Zapewnienie przechwycenia i obsługi zgłoszonych przez DBMS wyjątków związanych z realizacją kwerend w metodach biznesowych komponentu pełniącego rolę fasady wymaga wcześniejszego wymuszenia wykonania kwerend w bazie danych poprzez metodę EntityManager.flush()

### Informacje dostarczane przez wyjątek aplikacyjny
Klasa wyjątku aplikacyjnego powinna dostarczać wszystkich niezbędnych informacji do obsłużenia zaistniałej sytuacji błędu:
Jeżeli przyczyną zgłoszenia wyjątku aplikacyjnego był inny wyjątek, wówczas jego obiekt powinien zostać ustawiony jako przyczyna zgłoszenia wyjątku z wykorzystaniem konstruktora lub metody Throwable.initCause(),
Wyjątek aplikacyjny powinien zawierać informacje pozwalające zidentyfikować obiekty, których dotyczył błąd lub zaistniały problem, który był przyczyną zgłoszenia wyjątku,
Wyjątek aplikacyjny nie powinien bezpośrednio zawierać treści komunikatu, który zostanie przedstawiony w interfejsie użytkownika aplikacji biznesowej, zamiast treści komunikatu powinien zawierać klucz pozwalający dobrać treść komunikatu względem preferencji językowych interfejsu użytkownika.

### Propagacja wyjątku aplikacyjnego z warstwy logiki biznesowej do warstwy prezentacji
Wyjątki aplikacyjne mogą być obsługiwane bezpośrednio w warstwie logiki biznesowej lub propagowane do warstwy prezentacji w celu dalszego ich obsłużenia.
Propagacja weryfikowalnego wyjątku aplikacyjnego wymaga jawnego zgłaszania go przez każdą wywoływaną metodę biznesową komponentu EJB pośredniczącą w wywołaniu bloku kodu, w którym został zgłoszony weryfikowalny wyjątek.
W sytuacji wielu weryfikowalnych wyjątków aplikacyjnych, które mogą być zgłoszone przez metodę biznesową zaleca się wprowadzenie nadrzędnej klasy dla wyjątków aplikacyjnych. Wówczas tylko nadrzędną klasę wyjątków aplikacyjnych należy umieścić na liście zgłaszanych wyjątków przez metodę biznesową. Przedstawione rozwiązanie cechuje się elastycznością, ponieważ umożliwia wprowadzenie nowych wyjątków aplikacyjnych bez potrzeby zmian w sygnaturach metod biznesowych istniejących komponentów EJB, wystarczy że klasy nowo wprowadzonych weryfikowalnych wyjątków aplikacyjnych będą rozszerzały klasę bazową.

### Przechwycenie i obsługa wyjątku aplikacyjnego propagująceo z warstwy logiki biznesowej do warstwy prezentacji
Zgłoszony wyjątek aplikacyjny propagujący do warstwy prezentacji powinien odwołać bieżącą transakcję aplikacyjną i przenieść klucz do internacjonalizacji (ozn. I18n) umożliwiający dobór komunikatu błędu do obowiązującej w interfejsie użytkownika wersji językowej.
Jeżeli akcja użytkownika, w ramach wykonania której został zgłoszony wyjątek aplikacyjny:
 - powinna wyświetlić komunikat dotyczący wystąpienia błędu,
 - nie powinna powodować utraty danych wprowadzonych przez użytkownika do pól formularza internetowego oprócz pól przechowujących dane niejawne (np. hasła). Oznacza to, że niezakończona akcja zainicjowana przez użytkownika, w ramach której zgłoszony został wyjątek, nie powinna zmieniać bieżącej wyświetlonej w przeglądarce internetowej strony, na której powinien pojawić się komunikat błędu dostosowany do wersji językowej obowiązującej w interfejsie użytkownika.

### Obsługa wyjątku systemowego w warstwie Web aplikacji biznesowej
Programowa obsługa wyjątków systemowych w warstwie widoku Web aplikacji biznesowej powinna zostać skonstruowana z wykorzystaniem segmentu obsługi wyjątku zlokalizowanego centralnie, który może być zastosowany w implementacji wielu akcji.
Jeżeli warstwa widoku Web jest budowana z wykorzystaniem wzorca Model-View-Controller bazując na jakarta.faces.webapp.FacesServlet wówczas można stworzyć klasę obserwatora spełniającą kontrakt interfejsu jakarta.faces.event.ActionListener.
Zastosowanie obserwatora w warstwie Web aplikacji biznesowej jest przykładem programowania aspektowego i umożliwia otoczenie każdej wywoływanej metody akcji kodem zawartym w implementacji metody processAction().
```java
public interface ActionListener {

public void processAction(ActionEvent event) throws AbortProcessingException

}
```

### Lokalizacja segmentu obsługi wyjątku aplikacyjnego w warstwie Web
Segment obsługi wyjątku aplikacyjnego powinien być zlokalizowany w metodzie akcji (metoda wywoływana poprzez kontroler MVC w wyniku wykonania akcji w interfejsie użytkownika), jeżeli tylko metoda akcji wywołuje przynajmniej jedną metodę biznesową dostępowego komponentu EJB (endpoint), w wyniku wykonania której może zostać zgłoszony wyjątek aplikacyjny lub jego podklasy.
Liczba segmentów obsługi wyjątków występująca w pojedynczej metodzie akcji zarządzanego ziarna jest uzależniona od liczby możliwych do zgłoszenia wyjątków aplikacyjnych w trakcie wykonania wywołanych metod biznesowych. Mimo możliwości wystąpienia tego samego typu wyjątków w różnych metodach akcji, zwykle posiadają one różne segmenty jego obsługi, ponieważ sposób obsługi błędu jest ściśle powiązany z implementowaną w metodzie akcji funkcjonalnością. W metodzie akcji zarządzanego ziarna nie należy zamieszczać zbyt ogólnych segmentów obsługi wyjątków przechwytujących wszystkie zgłoszone wyjątki (w tym zgłoszone wyjątki systemowe).
Jeżeli obsługa wyjątku obejmuje również wyświetlenie komunikatu użytkownikowi, który zainicjował akcję, wówczas należy dostosować treść komunikatu do wersji językowej interfejsu użytkownika.


## 9 Obsługa błędów - dokumentacja ssbd

W naszym systemie użytkownik informowany jest o błędach za pomocą tymczasowych powiadomień typu "toast" wraz z odpowiednią wiadomością. W aplikacji jednej strony błędy z warstwy logiki są rozróżniane po kodach HTTP oraz zawartości ciała odpowiedzi, który zawiera odpowiedni klucz do internacjonalizacji wiadomości.

Wyjątki systemowe są także zamieniane na odpowiednią odpowiedź HTTP wraz z kodem lub też przepakowywane w wyjątek aplikacyjny i zamieniane. Obsługa odpowiedzi HTTP zawierających informacje o błędach odbywa się w komponentach prezentacyjnych oraz dedykowanych hookach, odpowiedzialnych za interakcję z backendem. Kluczowym elementem tej obsługi jest wykorzystanie biblioteki react-query do zarządzania cyklem życia żądań HTTP oraz biblioteki axios wraz z centralnym mechanizmem obsługi błędów (axiosErrorHandler).

### 9.1. Obsługa wyjątków aplikacyjnych (biznesowych)

Błędy biznesowe są obsługiwane lokalnie w komponentach i hookach z wykorzystaniem specyficznych komunikatów błędów. Przykład obsługi błędów biznesowych w komponencie logowania przedstawia Listing 3.17.1.

```typescript
const onSubmit = (values: FormSchema) => {
  if (is2faRequired) {
    if (!access2FAToken) {
      form.setError("root", {});
      return;
    }

    twoFactorMutation.mutate(
      { code: values.code || "", access2FAToken },
      {
        onSuccess: () => {
          setIs2faRequired(false);
          setAccess2FAToken("");
          navigate(ROUTES.HOME);
        },
        onError: () => {
          form.setError("code", {
            message: t("2fa.error.code_invalid"),
          });
        },
      }
    );
  } else {
    loginMutation.mutate(
      { login: values.login, password: values.password },
      {
        onSuccess: (data) => {
          if (data?.value) {
            const payload = JSON.parse(atob(data.value.split(".")[1]));
            if (payload.typ === "access2fa") {
              setAccess2FAToken(data.value);
              setIs2faRequired(true);
            } else {
              navigate(ROUTES.HOME);
            }
          }
        },
        onError: (error) => {
          const err = error as AxiosError;
          const status = err.response?.status;

          if (status === 401) {
            form.setError("password", {
              message: t("login.error.password_error"),
            });
          } else if (status === 404) {
            form.setError("login", {
              message: t("login.error.login_error"),
            });
          } else if (status === 428) {
            navigate(ROUTES.FORCE_CHANGE_PASSWORD, {
              state: { login: values.login }
            })
          } else {
            form.setError("root", {
              message: t("login.error.login_failed", {
                message: error.message,
              }),
            });
          }
        },
      }
    );
  }
};
```

**Listing 9.1. Obsługa błędów biznesowych w komponencie logowania**

Bardziej zaawansowana obsługa błędów biznesowych znajduje się w hooku rejestracji użytkownika, gdzie różne typy błędów są mapowane na odpowiednie komunikaty (Listing 3.17.2).

```typescript
export const useRegisterUser = (userType: "client" | "dietician" | "admin") => {
  const { t } = useTranslation();
  return useMutation({
    mutationFn: (payload: RegisterUserRequest) =>
      registerUser(userType, payload),
    onSuccess: () => {
      toast.success(t("register.success"));
    },
    onError: (error: unknown) => {
      if (axios.isAxiosError(error)) {
        const status = error.response?.status;
        const data = error.response?.data;

        if (status === 409) {
          if (data.message === "account_constraint_violation: email already in use") {
            toast.error(t("register.error.emailExist"));
          } else if (
              data.message === "account_constraint_violation: login already in use"
          ) {
            toast.error(t("register.error.loginExist"));
          }
        } else if (status === 403) {
          toast.error(t("register.error.accessDenied"));
        } else if (status === 401) {
          toast.error(t("register.error.unauthorized"));
        } else if (status === 400) {
          const violations = data?.violations;
          if (Array.isArray(violations)) {
            const passwordViolation = violations.find(
              (v) => v.fieldName === "account.password"
            );
            if (passwordViolation) {
              toast.error(t("register.error.passwordRegex"));
              return;
            }
            [...]
          }
          toast.error("Nie powinno Cię tu być");
        } else {
          axiosErrorHandler(error, t("register.error.generic"));
        }
      } else {
        toast.error(t("register.error.unknown"));
      }
    },
  });
};
```

**Listing 9.2. Obsługa błędów biznesowych w hooku rejestracji**

### 9.2. Obsługa wyjątków systemowych

Wyjątki systemowe są przechwytywane przez interceptory HTTP w centralnym kliencie API. Interceptor odpowiedzi obsługuje różne typy błędów systemowych i mapuje je na odpowiednie komunikaty użytkownika (Listing 3.17.3).

```typescript
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (
      error.response &&
      error.response.status === 401 &&
      !originalRequest._retry
    ) {
      if (!window.location.pathname.includes("/login")) {
        localStorage.removeItem("token");
      }

      if (isRefreshing) {
        return new Promise(function (resolve, reject) {
          failedQueue.push({ resolve, reject});
        })
        .then(token => {
          originalRequest.headers["Authorization"] = `Bearer ${token}`;
          return apiClient(originalRequest);
        })
        .catch (err => {
          return Promise.reject(err);
        })
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const refreshRes = await authClient.post("/account/refresh");
        const { value } = refreshRes.data;
        localStorage.setItem("token", value);

        apiClient.defaults.headers.common["Authorization"] = `Bearer ${value}`;
        processQueue(null, value);

        return apiClient(originalRequest);
      } catch (err) {
        processQueue(err, null)
        localStorage.removeItem("token");
        return Promise.reject(err);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);
```


### 9.3. Konfiguracja reakcji na błąd HTTP 401

Błąd HTTP 401 (Unauthorized) jest obsługiwany w sposób szczególny poprzez mechanizm automatycznego odświeżania tokenów dostępu. System implementuje kolejkę żądań, które oczekują na odświeżenie tokenu, co zapobiega wielokrotnym próbom odświeżenia (Listing 3.17.4).

```typescript
let isRefreshing = false;

type FailedRequest = {
  resolve: (token: string | null) => void;
  reject: (error: unknown) => void;
};

let failedQueue: FailedRequest[] = [];

const processQueue = (error: unknown, token: string | null = null) => {
  failedQueue.forEach(prom => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });

  failedQueue = [];
};
```

**Listing 9.4. Mechanizm obsługi błędu 401 z refresh token**

```typescript
let isRefreshing = false;

type FailedRequest = {
  resolve: (token: string | null) => void;
  reject: (error: unknown) => void;
};

let failedQueue: FailedRequest[] = [];

const processQueue = (error: unknown, token: string | null = null) => {
  failedQueue.forEach(prom => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });

  failedQueue = [];
};
```

**Listing 9.4. Mechanizm obsługi błędu 401 z refresh token**

### 9.4. Centralny handler błędów HTTP

Funkcja `axiosErrorHandler` stanowi centralny punkt obsługi błędów HTTP w aplikacji. Mapuje kody błędów na odpowiednie komunikaty z systemu internacjonalizacji (Listing 3.17.5).

```typescript
export const axiosErrorHandler = (
  error: unknown,
  fallbackMessage = "An unexpected error occurred"
) => {
  if (axios.isAxiosError(error)) {
    const status = error.response?.status;

    if (status === 500) {
      toast.error(i18n.t("exceptions.unexpected"));
      return;
    }

    const message =
      error.response?.data?.message ||
      error.response?.data?.error ||
      error.message ||
      fallbackMessage;

    toast.error(i18n.t("exceptions." + message));
  } else {
    console.log("Unknown error:", error);
  }
};
```

**Listing 9.5. Centralny handler błędów HTTP**

### 9.5. Mapowanie komunikatów błędów w systemie internacjonalizacji

System wykorzystuje klucze internacjonalizacji do wyświetlania komunikatów błędów w języku polskim. Przykład mapowania komunikatów błędów przedstawia Listing 3.17.6.

```typescript
{
  "exceptions": {
    "account_is_autolocked": "Konto nie było używane od dłuższego czasu! Sprawdź swoją skrzynkę odbiorczą, aby znaleźć link aktywacyjny!",
    "account_already_blocked": "Konto jest już zablokowane",
    "account_not_found": "Nie znaleziono konta",
    "account_not_verified": "Konto nie zostało zweryfikowane",
    "invalid_credentials": "Nieprawidłowe dane logowania",
    "excessive_login_attempts": "Zbyt wiele nieudanych prób logowania. Konto zostało tymczasowo zablokowane.",
    "token_expired": "Żeton wygasł",
    [...]
    "unauthorized": "Brak uwierzytelnienia",
    "access_denied": "Odmowa dostępu",
    "unexpected": "Wystąpił niespodziewany błąd, spróbuj ponownie później."
  }
}
```

**Listing 9.6. Fragment pliku lokalizacji z komunikatami błędów**

![Rys. 17.1](/img/Rys.17.1.png)

Rys. 9.1. Komunikat o błędzie wyświetlany użytkownikowi w postaci powiadomienia toast.

![Rys. 17.2](/img/Rys.17.2.png)

Rys. 9.2. Przykład powiadomienia o nieoczekiwanym błędzie.

![Rys. 17.3](/img/Rys.17.3.png)

Rys. 9.3. Przykład błędu walidacji formularza logowania.

### 10. Wyjątki aplikacyjne

Wszystkie wyjątki aplikacyjne dziedziczą po klasie `AppBaseException`:

```java
public abstract class AppBaseException extends ResponseStatusException {
    protected AppBaseException(HttpStatusCode status, String reason) {
        super(status, reason);
    }

    protected AppBaseException(HttpStatusCode status, String reason, Throwable cause) {
        super(status, reason, cause);
    }
}
```

### 1. Wyjątki błędnych żądań (400 Bad Request)

#### 1.1 `PreviousPasswordUsedException`

- **Miejsca zgłoszenia**: `AccountService.changePassword()`, `AccountService.resetPassword()`
- **Klucz internacjonalizacji**: `previous_password_used`
- **Kod błędu HTTP**: 400
- **Możliwe przyczyny wystąpienia**: Próba ustawienia hasła, które było już wcześniej używane przez użytkownika
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 400 z wiadomością z klucza `previous_password_used`
- **Odwołanie transakcji**: Tak


#### 1.2 `InvalidBloodParameterException`

- **Miejsca zgłoszenia**: `BloodTestResultService.createBloodTestResult()`
- **Klucz internacjonalizacji**: `invalid_blood_parameter_name`
- **Kod błędu HTTP**: 400
- **Możliwe przyczyny wystąpienia**: Próba utworzenia wyniku badania krwi z nieprawidłowym parametrem krwi
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 400 z wiadomością z klucza `invalid_blood_parameter_name`
- **Odwołanie transakcji**: Tak


#### 1.3 `PeriodicSurveyTooSoonException`

- **Miejsca zgłoszenia**: `ClientModService.submitPeriodicSurvey()`
- **Klucz internacjonalizacji**: `periodic_survey_too_soon`
- **Kod błędu HTTP**: 400
- **Możliwe przyczyny wystąpienia**: Próba przesłania ankiety okresowej przed upływem 24 godzin od ostatniej
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 400 z wiadomością z klucza `periodic_survey_too_soon`
- **Odwołanie transakcji**: Tak


#### 1.4 `AccountSameEmailException`

- **Miejsca zgłoszenia**: `AccountService.changeOwnEmail()`, `AccountService.changeUserEmail()`
- **Klucz internacjonalizacji**: `account_same_email`
- **Kod błędu HTTP**: 400
- **Możliwe przyczyny wystąpienia**: Próba zmiany email na ten sam, który już jest ustawiony
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 400 z wiadomością z klucza `account_same_email`
- **Odwołanie transakcji**: Tak


#### 1.5 `InvalidLockTokenException`

- **Miejsca zgłoszenia**: `AccountService.updateAccount()`, `ClientModService.editPermanentSurvey()`, `ClientModService.editPeriodicSurvey()`
- **Klucz internacjonalizacji**: `invalid_lock_token`
- **Kod błędu HTTP**: 400
- **Możliwe przyczyny wystąpienia**: Próba modyfikacji zasobu z nieprawidłowym tokenem blokady
- **Blokady optymistyczne**: **TAK** - związane z mechanizmem blokad optymistycznych, token zawiera ID i wersję zasobu
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 400 z wiadomością z klucza `invalid_lock_token`
- **Odwołanie transakcji**: Tak


### 2. Wyjątki nieautoryzowanego dostępu (401 Unauthorized)

#### 2.1 `InvalidCredentialsException`

- **Miejsca zgłoszenia**: `AccountService.login()`, `AccountService.changePassword()`, `AccountService.forceChangePassword()`
- **Klucz internacjonalizacji**: `invalid_credentials`
- **Kod błędu HTTP**: 401
- **Możliwe przyczyny wystąpienia**: Niepoprawne hasło podczas logowania lub zmiany hasła
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 401 z wiadomością z klucza `invalid_credentials`. **UWAGA**: W metodzie `login()` jest `noRollbackFor` - transakcja NIE jest wycofywana, więc zapis informacji o nieudanej próbie logowania zostaje zachowany
- **Odwołanie transakcji**: **NIE** (tylko w `login()`), **TAK** (w pozostałych)


#### 2.2 `TwoFactorTokenInvalidException`

- **Miejsca zgłoszenia**: `AccountService.verifyTwoFactorCode()`
- **Klucz internacjonalizacji**: `two_factor_token_invalid`
- **Kod błędu HTTP**: 401
- **Możliwe przyczyny wystąpienia**: Niepoprawny kod weryfikacji dwuskładnikowej
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 401 z wiadomością z klucza `two_factor_token_invalid`
- **Odwołanie transakcji**: Tak


#### 2.3 `TokenExpiredException`

- **Miejsca zgłoszenia**: `AccountService.verifyTwoFactorCode()`,
  `AccountService.confirmEmail()`,
  `AccountService.revertEmailChange()`,
  `AccountService.verifyAccount()`,
  `AccountService.unlockAccount()`,
  `PasswordResetTokenService.validatePasswordResetToken()`,
  `JwtTokenProvider.validateToken()`,
- **Klucz internacjonalizacji**: `token_expired`
- **Kod błędu HTTP**: 401
- **Możliwe przyczyny wystąpienia**: Próba użycia wygasłego tokenu weryfikacyjnego/zmiany email
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Specjalny handler** - `GeneralControllerExceptionHandler.handleTokenBaseException()` tworzy JSON z polami: `{"error": "Authorization exception", "message": "token_expired", "status": 401, "timestamp": "2025-01-22T15:03:07"}`
- **Odwołanie transakcji**: Tak

#### 2.4 `TokenInvalidException`

- **Miejsca zgłoszenia**: Wszystkie operacje z żetonami
- **Klucz internacjonalizacji**: `token_signature_invalid`
- **Kod błędu HTTP**: 401
- **Możliwe przyczyny wystąpienia**: Próba użycia nieprawidłowego tokenu
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Specjalny handler** - `GeneralControllerExceptionHandler.handleTokenBaseException()` tworzy JSON z polami: `{"error": "Authorization exception", "message": "token_signature_invalid", "status": 401, "timestamp": "..."}`
- **Odwołanie transakcji**: Tak


#### 2.5 `TokenNotFoundException`

- **Miejsca zgłoszenia**: `AccountService.verifyTwoFactorCode()`,
  `AccountService.resetPassword()`,
  `AccountService.confirmEmail()`,
  `AccountService.revertEmailChange()`,
  `AccountService.verifyAccount()`,
  `AccountService.unlockAccount()`,
  `AccountService.authWithEmail()`,
  `JwtService.refresh()`,
  `PasswordResetTokenService.validatePasswordResetToken()`,
  `JwtAuthFilter.doFilterInternal()`
- **Klucz internacjonalizacji**: `token_not_found`
- **Kod błędu HTTP**: 401
- **Możliwe przyczyny wystąpienia**: Próba użycia nieistniejącego tokenu
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Specjalny handler** - `GeneralControllerExceptionHandler.handleTokenBaseException()` tworzy JSON z polami: `{"error": "Authorization exception", "message": "token_not_found", "status": 401, "timestamp": "..."}`
- **Odwołanie transakcji**: Tak



### 3. Wyjątki braku uprawnień (403 Forbidden)

#### 3.1 `AccountNotActiveException`

- **Miejsca zgłoszenia**: `AccountService.login()`, `AccountService.updateAccount()` `AccountService.authWithEmail()`
- **Klucz internacjonalizacji**: `account_not_active`
- **Kod błędu HTTP**: 403
- **Możliwe przyczyny wystąpienia**: Próba logowania lub modyfikacji zablokowanego konta
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 403 z wiadomością z klucza `account_not_active`
- **Odwołanie transakcji**: Tak


#### 3.2 `AccountNotVerifiedException`

- **Miejsca zgłoszenia**: `AccountService.login()`, `AccountService.authWithEmail()`
- **Klucz internacjonalizacji**: `account_not_verified`
- **Kod błędu HTTP**: 403
- **Możliwe przyczyny wystąpienia**: Próba logowania na niezweryfikowane konto
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 403 z wiadomością z klucza `account_not_verified`
- **Odwołanie transakcji**: Tak


#### 3.3 `SelfBlockAccountException`

- **Miejsca zgłoszenia**: `AccountService.blockAccount()`
- **Klucz internacjonalizacji**: `self_block`
- **Kod błędu HTTP**: 403
- **Możliwe przyczyny wystąpienia**: Administrator próbuje zablokować własne konto
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 403 z wiadomością z klucza `self_block`
- **Odwołanie transakcji**: Tak


#### 3.4 `SelfRoleAssignmentException`

- **Miejsca zgłoszenia**: `AccountService.assignRole()`, `AccountService.unassignRole()`
- **Klucz internacjonalizacji**: `self_role_assignment`
- **Kod błędu HTTP**: 403
- **Możliwe przyczyny wystąpienia**: Administrator próbuje zmienić własne uprawnienia
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 403 z wiadomością z klucza `self_role_assignment`
- **Odwołanie transakcji**: Tak


#### 3.5 `PasswordToChangeException`

- **Miejsca zgłoszenia**: `AccountService.login()`
- **Klucz internacjonalizacji**: `authentication_failure`
- **Kod błędu HTTP**: 403
- **Możliwe przyczyny wystąpienia**: Logowanie z hasłem wymagającym obowiązkowej zmiany
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 403 z wiadomością z klucza `authentication_failure`
- **Odwołanie transakcji**: Tak


#### 3.6 `DieticianAccessDeniedException`

- **Miejsca zgłoszenia**: `DieticianModService.orderMedicalExaminations()`, `DieticianModService.getDieticiansClientById()`, `ClientBloodTestReportService.createReport()`
- **Klucz internacjonalizacji**: `dietician_access_denied`
- **Kod błędu HTTP**: 403
- **Możliwe przyczyny wystąpienia**: Dietetyk próbuje uzyskać dostęp do klienta, który nie jest mu przypisany
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 403 z wiadomością z klucza `dietician_access_denied`
- **Odwołanie transakcji**: Tak


#### 3.7 `NotYourFeedbackException`

- **Miejsca zgłoszenia**: `FeedbackService.updateFeedback()`, `FeedbackService.deleteFeedback()`
- **Klucz internacjonalizacji**: `not_your_feedback`
- **Kod błędu HTTP**: 403
- **Możliwe przyczyny wystąpienia**: Próba modyfikacji opinii należącej do innego użytkownika
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 403 z wiadomością z klucza `not_your_feedback`
- **Odwołanie transakcji**: Tak


#### 3.8 `NotYourFoodPyramidException`

- **Miejsca zgłoszenia**: `ClientFoodPyramidService.rateFoodPyramid()`
- **Klucz internacjonalizacji**: `not_your_pyramid`
- **Kod błędu HTTP**: 403
- **Możliwe przyczyny wystąpienia**: Próba oceny piramidy żywieniowej nieprzypisanej do użytkownika
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 403 z wiadomością z klucza `not_your_pyramid`
- **Odwołanie transakcji**: Tak


#### 3.9 `AccountHasNoRolesException`

- **Miejsca zgłoszenia**: `AccountService.login()`, `AccountService.authWithEmail()`, `JwtService.refresh()`
- **Klucz internacjonalizacji**: `account_has_no_roles`
- **Kod błędu HTTP**: 403
- **Możliwe przyczyny wystąpienia**: Próba logowania na konto bez przypisanych aktywnych ról
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 403 z wiadomością z klucza `account_has_no_roles`
- **Odwołanie transakcji**: Tak


#### 3.10 `AuthorizationDeniedException`

- **Miejsca zgłoszenia**: Wszystkie metody chronione przez `SecurityConfig` i/lub z `@PreAuthorize` w przypadku brak uprawnień
- **Klucz internacjonalizacji**: Brak (wyjątek systemowy)
- **Kod błędu HTTP**: 403
- **Możliwe przyczyny wystąpienia**: Próba wywołania metody bez odpowiednich uprawnień (role ADMIN, CLIENT, DIETICIAN)
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Specjalny handler** - `GeneralControllerExceptionHandler.handleAuthorizationException()` loguje próbę nieautoryzowanego dostępu do pliku log i zwraca `ResponseEntity.status(403).body("Authorization exception: " + exception.getMessage())`
- **Odwołanie transakcji**: Tak


### 4. Wyjątki braku zasobu (404 Not Found)

#### 4.1 `AccountNotFoundException`

- **Miejsca zgłoszenia**: `AccountService.changePassword()`,
  `AccountService.forceChangePassword()`,
  `AccountService.setGeneratedPassword()`,
  `AccountService.login()`,
  `AccountService.verifyTwoFactorCode()`,
  `AccountService.logout()`,
  `AccountService.blockAccount()`,
  `AccountService.unblockAccount()`,
  `AccountService.resetPassword()`,
  `AccountService.changeOwnEmail()`,
  `AccountService.changeUserEmail()`,
  `AccountService.confirmEmail()`,
  `AccountService.revertEmailChange()`,
  `AccountService.resendEmailChangeLink()`,
  `AccountService.getAccountByLogin()`,
  `AccountService.getAccountById()`,
  `AccountService.updateAccountById()`,
  `AccountService.logUserRoleChange()`,
  `AccountService.updateMyAccount()`,
  `AccountService.AccountNotFoundException()`,
  `AccountService.assignRole()`,
  `AccountService.unassignRole()`,
  `AccountService.enableTwoFactor()`,
  `AccountService.disableTwoFactor()`,
  `JwtService.refresh()`
- **Klucz internacjonalizacji**: `account_not_found`
- **Kod błędu HTTP**: 404
- **Możliwe przyczyny wystąpienia**: Próba dostępu do nieistniejącego konta użytkownika
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 404 z wiadomością z klucza `account_not_found`
- **Odwołanie transakcji**: Tak


#### 4.2 `ClientNotFoundException`

- **Miejsca zgłoszenia**: `AlgorithmService.generateFoodPyramid()`,
  `ClientBloodTestReportService.getClientBloodTestReportDTOS()`,
  `ClientBloodTestReportService.createReport()`,
  `ClientFoodPyramidService.assignFoodPyramidToClient()`,
  `ClientFoodPyramidService.getClientPyramids()`,
  `ClientFoodPyramidService.getClientPyramidsByDietician()`,
  `ClientFoodPyramidService.getMyCurrentPyramid()`,
  `ClientFoodPyramidService.getCurrentPyramid()`,
  `ClientModService.getClientById()`,
  `ClientModService.getClientByLogin()`,
  `ClientModService.assignDietician()`,
  `ClientModService.getClientStatus()`,
  `ClientModService.submitPermanentSurvey()`,
  `ClientModService.getPermanentSurvey()`,
  `ClientModService.submitPeriodicSurvey()`,
  `ClientModService.editPermanentSurvey()`,
  `ClientModService.getPeriodicSurveys()`,
  `ClientModService.editPeriodicSurvey()`,
  `ClientModService.getMyLatestPeriodicSurvey()`,
  `ClientModService.getBloodTestOrder()`,
  `DieticianModService.getClientDetails()`,
  `DieticianModService.orderMedicalExaminations()`,
  `DieticianModService.getDieticiansClientById()`,
  `DieticianModService.getPeriodicSurveysByClientId()`,
  `DieticianModService.getLastOrder()`,
  `FeedbackService.getFeedbackByClientLoginAndPyramid()`,
  `FeedbackService.addFeedback()`,
  `FeedbackService.deleteFeedback()`,
  `FeedbackService.updateFeedback()`
- **Klucz internacjonalizacji**: `client_not_found`
- **Kod błędu HTTP**: 404
- **Możliwe przyczyny wystąpienia**: Próba dostępu do nieistniejącego klienta
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 404 z wiadomością z klucza `client_not_found`
- **Odwołanie transakcji**: Tak


#### 4.3 `DieticianNotFoundException`

- **Miejsca zgłoszenia**: `ClientBloodTestReportService.createReport()`,
  `ClientFoodPyramidService.getClientPyramidsByDietician()`,
  `ClientModService.assignDietician()`,
  `DieticianModService.getClientsByDietician()`,
  `DieticianModService.orderMedicalExaminations()`,
  `DieticianModService.getDieticiansClientById()`,
  `DieticianModService.getUnfulfilledBloodTestOrders()`
- **Klucz internacjonalizacji**: `dietician_not_found`
- **Kod błędu HTTP**: 404
- **Możliwe przyczyny wystąpienia**: Próba dostępu do nieistniejącego dietetyka
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 404 z wiadomością z klucza `dietician_not_found`
- **Odwołanie transakcji**: Tak



#### 4.4 `RoleNotFoundException`

- **Miejsca zgłoszenia**: `AccountService.unassignRole()`
- **Klucz internacjonalizacji**: `role_not_found`
- **Kod błędu HTTP**: 404
- **Możliwe przyczyny wystąpienia**: Próba usunięcia roli, która nie jest przypisana do użytkownika
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 404 z wiadomością z klucza `role_not_found`
- **Odwołanie transakcji**: Tak


#### 4.5 `SurveyNotFoundException`

- **Miejsca zgłoszenia**: `BloodParameterController.getAllBloodParameters()`,
  `AlgorithmService.generateFoodPyramid()`,
  `ClientModService.getPermanentSurvey()`,
  `DieticianModService.getPermanentSurveyByClientId()`
- **Klucz internacjonalizacji**: `permanent_survey_not_found`
- **Kod błędu HTTP**: 404
- **Możliwe przyczyny wystąpienia**: Próba dostępu do nieistniejącej ankiety stałej
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 404 z wiadomością z klucza `permanent_survey_not_found`
- **Odwołanie transakcji**: Tak



#### 4.6 `PeriodicSurveyNotFound`

- **Miejsca zgłoszenia**: `ClientModService.getPeriodicSurvey()`,
  `ClientModService.getPeriodicSurveys()`,
  `ClientModService.editPeriodicSurvey()`,
  `ClientModService.getMyLatestPeriodicSurvey()`,
  `DieticianModService.getPeriodicSurveysByClientId()`
- **Klucz internacjonalizacji**: `periodic_survey_not_found`
- **Kod błędu HTTP**: 404
- **Możliwe przyczyny wystąpienia**: Próba dostępu do nieistniejącej ankiety okresowej
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 404 z wiadomością z klucza `periodic_survey_not_found`
- **Odwołanie transakcji**: Tak


#### 4.7 `FoodPyramidNotFoundException`

- **Miejsca zgłoszenia**: `ClientFoodPyramidService.assignFoodPyramidToClient()`,
  `ClientFoodPyramidService.createAndAssignFoodPyramid()`,
  `ClientFoodPyramidService.getLatestClientFoodPyramidDto()`,
  `FeedbackService.getFeedbackByClientLoginAndPyramid()`,
  `FeedbackService.addFeedback()`,
  `FeedbackService.updateFeedback()`,
  `FoodPyramidService.getById()`
- **Klucz internacjonalizacji**: `food_pyramid_not_found`
- **Kod błędu HTTP**: 404
- **Możliwe przyczyny wystąpienia**: Próba dostępu do nieistniejącej piramidy żywieniowej
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 404 z wiadomością z klucza `food_pyramid_not_found`
- **Odwołanie transakcji**: Tak


#### 4.8 `BloodTestOrderNotFoundException`

- **Miejsca zgłoszenia**: `ClientModService.getBloodTestOrder()`, `DieticianModService.confirmBloodTestOrder()`
- **Klucz internacjonalizacji**: `blood_test_order_not_found`
- **Kod błędu HTTP**: 404
- **Możliwe przyczyny wystąpienia**: Próba dostępu do nieistniejącego zlecenia badań krwi
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 404 z wiadomością z klucza `blood_test_order_not_found`
- **Odwołanie transakcji**: Tak


#### 4.9 `BloodTestResultNotFoundException`

- **Miejsca zgłoszenia**: `BloodTestResultService.getBloodTestResultById()`
- **Klucz internacjonalizacji**: `blood_test_result_not_found`
- **Kod błędu HTTP**: 404
- **Możliwe przyczyny wystąpienia**: Próba dostępu do nieistniejącego wyniku badania krwi
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 404 z wiadomością z klucza `blood_test_result_not_found`
- **Odwołanie transakcji**: Tak


#### 4.10 `ClientBloodTestReportNotFoundException`

- **Miejsca zgłoszenia**: `AlgorithmService.generateFoodPyramid()`,
  `ClientBloodTestReportService.getClientBloodTestReportDTOS()`,
  `ClientBloodTestReportService.getById()`,
  `ClientBloodTestReportService.updateReport()`
- **Klucz internacjonalizacji**: `client_blood_test_report_not_found`
- **Kod błędu HTTP**: 404
- **Możliwe przyczyny wystąpienia**: Próba dostępu do nieistniejącego raportu badań krwi klienta
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 404 z wiadomością z klucza `client_blood_test_report_not_found`
- **Odwołanie transakcji**: Tak


#### 4.11 `FeedbackNotFoundException`

- **Miejsca zgłoszenia**: `FeedbackService.getFeedbackByClientLoginAndPyramid()`,
  `FeedbackService.deleteFeedback()`,
  `FeedbackService.updateFeedback()`
- **Klucz internacjonalizacji**: `feedback_not_found`
- **Kod błędu HTTP**: 404
- **Możliwe przyczyny wystąpienia**: Próba dostępu do nieistniejącej opinii
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 404 z wiadomością z klucza `feedback_not_found`
- **Odwołanie transakcji**: Tak


#### 4.12 `ClientFoodPyramidNotFoundException`

- **Miejsca zgłoszenia**: `ClientFoodPyramidService.getClientFoodPyramid()`
- **Klucz internacjonalizacji**: `client_food_pyramid_not_found`
- **Kod błędu HTTP**: 404
- **Możliwe przyczyny wystąpienia**: Próba dostępu do nieprzypisanej piramidy żywieniowej klienta
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 404 z wiadomością z klucza `client_food_pyramid_not_found`
- **Odwołanie transakcji**: Tak


#### 4.13 `EmailChangeTokenNotFoundException`

- **Miejsca zgłoszenia**: `AccountService.resendEmailChangeLink()`
- **Klucz internacjonalizacji**: `email_change_token_not_found`
- **Kod błędu HTTP**: 404
- **Możliwe przyczyny wystąpienia**: Próba ponownego wysłania linku zmiany email, gdy nie ma aktywnego tokenu
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 404 z wiadomością z klucza `email_change_token_not_found`
- **Odwołanie transakcji**: Tak


### 5. Wyjątki konfliktów danych (409 Conflict)

#### 5.1 `ConcurrentUpdateException`

- **Miejsca zgłoszenia**: Wszystkie metody z `@Retryable`, `AccountService.updateAccount()`, `ClientModService.editPermanentSurvey()`
- **Klucz internacjonalizacji**: `concurrent_update`
- **Kod błędu HTTP**: 409
- **Możliwe przyczyny wystąpienia**: Jednoczesna modyfikacja tego samego zasobu przez różnych użytkowników
- **Blokady optymistyczne**: **TAK** - główny mechanizm obsługi blokad optymistycznych. Wyjątek jest zgłaszany przez `GenericOptimisticLockHandlingInterceptor` po przechwyceniu `OptimisticLockingFailureException`
- **Sposób obsługi**: **Mechanizm retry + Spring** - 1) `@Retryable` automatycznie ponawia operację 3 razy z opóźnieniem 1000ms, 2) Po wyczerpaniu prób wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 409 z wiadomością z klucza `concurrent_update`
- **Odwołanie transakcji**: Tak


#### 5.2 `AccountEmailAlreadyInUseException`

- **Miejsca zgłoszenia**: `AccountService.changeOwnEmail()`, `AccountService.changeUserEmail()`
- **Klucz internacjonalizacji**: `account_email_already_in_use`
- **Kod błędu HTTP**: 409
- **Możliwe przyczyny wystąpienia**: Próba zmiany na adres email już używany przez inne konto
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 409 z wiadomością z klucza `account_email_already_in_use`
- **Odwołanie transakcji**: Tak


#### 5.3 `AccountAlreadyBlockedException`

- **Miejsca zgłoszenia**: `AccountService.blockAccount()`
- **Klucz internacjonalizacji**: `account_already_blocked`
- **Kod błędu HTTP**: 409
- **Możliwe przyczyny wystąpienia**: Próba zablokowania już zablokowanego konta
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 409 z wiadomością z klucza `account_already_blocked`
- **Odwołanie transakcji**: Tak


#### 5.4 `AccountAlreadyUnblockedException`

- **Miejsca zgłoszenia**: `AccountService.unblockAccount()`
- **Klucz internacjonalizacji**: `account_already_unblocked`
- **Kod błędu HTTP**: 409
- **Możliwe przyczyny wystąpienia**: Próba odblokowania już odblokowanego konta
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 409 z wiadomością z klucza `account_already_unblocked`
- **Odwołanie transakcji**: Tak


#### 5.5 `AccountAlreadyVerifiedException`

- **Miejsca zgłoszenia**: `AccountService.verifyAccount()`
- **Klucz internacjonalizacji**: `account_already_verified`
- **Kod błędu HTTP**: 409
- **Możliwe przyczyny wystąpienia**: Próba weryfikacji już zweryfikowanego konta
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 409 z wiadomością z klucza `account_already_verified`
- **Odwołanie transakcji**: Tak


#### 5.6 `RoleConflictException`

- **Miejsca zgłoszenia**: `AccountService.assignRole()`
- **Klucz internacjonalizacji**: `role_conflict`
- **Kod błędu HTTP**: 409
- **Możliwe przyczyny wystąpienia**: Próba przypisania konfliktowych ról (CLIENT i DIETICIAN jednocześnie)
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 409 z wiadomością z klucza `role_conflict`
- **Odwołanie transakcji**: Tak


#### 5.7 `DieticianAlreadyAssignedException`

- **Miejsca zgłoszenia**: `ClientModService.assignDietician()`
- **Klucz internacjonalizacji**: `dietician_already_assigned`
- **Kod błędu HTTP**: 409
- **Możliwe przyczyny wystąpienia**: Próba przypisania dietetyka do klienta, który już ma przypisanego dietetyka
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 409 z wiadomością z klucza `dietician_already_assigned`
- **Odwołanie transakcji**: Tak


#### 5.8 `SameDieticianAlreadyAssignedException`

- **Miejsca zgłoszenia**: `ClientModService.assignDietician()`
- **Klucz internacjonalizacji**: `same_dietician_already_assigned`
- **Kod błędu HTTP**: 409
- **Możliwe przyczyny wystąpienia**: Próba przypisania tego samego dietetyka, który już jest przypisany
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 409 z wiadomością z klucza `same_dietician_already_assigned`
- **Odwołanie transakcji**: Tak


#### 5.9 `PermanentSurveyAlreadyExistsException`

- **Miejsca zgłoszenia**: `ClientModService.submitPermanentSurvey()`
- **Klucz internacjonalizacji**: `permanent_survey_already_exists`
- **Kod błędu HTTP**: 409
- **Możliwe przyczyny wystąpienia**: Próba przesłania ankiety stałej przez klienta, który już ją wypełnił
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 409 z wiadomością z klucza `permanent_survey_already_exists`
- **Odwołanie transakcji**: Tak


#### 5.10 `FoodPyramidAlreadyAssignedException`

- **Miejsca zgłoszenia**: `ClientFoodPyramidService.assignFoodPyramid()`
- **Klucz internacjonalizacji**: `food_pyramid_already_assigned`
- **Kod błędu HTTP**: 409
- **Możliwe przyczyny wystąpienia**: Próba przypisania piramidy żywieniowej, która już jest przypisana do klienta
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 409 z wiadomością z klucza `food_pyramid_already_assigned`
- **Odwołanie transakcji**: Tak


#### 5.11 `AlreadyRatedPyramidException`

- **Miejsca zgłoszenia**: `ClientFoodPyramidService.rateFoodPyramid()`
- **Klucz internacjonalizacji**: `pyramid_already_rated`
- **Kod błędu HTTP**: 409
- **Możliwe przyczyny wystąpienia**: Próba ponownej oceny już ocenionej piramidy żywieniowej
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 409 z wiadomością z klucza `pyramid_already_rated`
- **Odwołanie transakcji**: Tak


#### 5.12 `BloodTestAlreadyOrderedException`

- **Miejsca zgłoszenia**: `DieticianModService.orderMedicalExaminations()`
- **Klucz internacjonalizacji**: `blood_test_already_ordered`
- **Kod błędu HTTP**: 409
- **Możliwe przyczyny wystąpienia**: Próba zlecenia badań krwi dla klienta, który ma już niezrealizowane zlecenie
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 409 z wiadomością z klucza `blood_test_already_ordered`
- **Odwołanie transakcji**: Tak


#### 5.13 `BloodTestOrderAlreadyFulfilledException`

- **Miejsca zgłoszenia**: `DieticianModService.confirmBloodTestOrder()`
- **Klucz internacjonalizacji**: `blood_test_already_fulfilled`
- **Kod błędu HTTP**: 409
- **Możliwe przyczyny wystąpienia**: Próba potwierdzenia już zrealizowanego zlecenia badań
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 409 z wiadomością z klucza `blood_test_already_fulfilled`
- **Odwołanie transakcji**: Tak


#### 5.14 `AccountTwoFactorAlreadyEnabled`

- **Miejsca zgłoszenia**: `AccountService.enableTwoFactor()`
- **Klucz internacjonalizacji**: `account_two_factor_already_enabled`
- **Kod błędu HTTP**: 409
- **Możliwe przyczyny wystąpienia**: Próba włączenia już włączonej autoryzacji dwuskładnikowej
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 409 z wiadomością z klucza `account_two_factor_already_enabled`
- **Odwołanie transakcji**: Tak


#### 5.15 `AccountTwoFactorAlreadyDisabled`

- **Miejsca zgłoszenia**: `AccountService.disableTwoFactor()`
- **Klucz internacjonalizacji**: `account_two_factor_already_disabled`
- **Kod błędu HTTP**: 409
- **Możliwe przyczyny wystąpienia**: Próba wyłączenia już wyłączonej autoryzacji dwuskładnikowej
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 409 z wiadomością z klucza `account_two_factor_already_disabled`
- **Odwołanie transakcji**: Tak


#### 5.16 `FoodPyramidNameAlreadyInUseException`

- **Miejsca zgłoszenia**: `ClientFoodPyramidService.createAndAssignFoodPyramid()`
- **Klucz internacjonalizacji**: `food_pyramid_name_already_in_use`
- **Kod błędu HTTP**: 409
- **Możliwe przyczyny wystąpienia**: Naruszenie unikalności nazwy
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Interceptor AOP** - `AccountConstraintViolationsHandlingInterceptor` przechwytuje `DataIntegrityViolationException` i przekształca w `AccountConstraintViolationException`, następnie **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 409 z wiadomością z klucza `food_pyramid_name_key`
- **Odwołanie transakcji**: Tak

### 6. Wyjątki ograniczeń biznesowych (422 Unprocessable Entity / 423 Locked / 429 Too Many Requests)

#### 6.1 `AccountIsAutolockedException`

- **Miejsca zgłoszenia**: `AccountService.login()`
- **Klucz internacjonalizacji**: `account_is_autolocked`
- **Kod błędu HTTP**: 423
- **Możliwe przyczyny wystąpienia**: Próba logowania na konto autozablokowane z powodu podejrzanej aktywności
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie + noRollbackFor** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 423 z wiadomością z klucza `account_is_autolocked`. **UWAGA**: `noRollbackFor` w metodzie `login()` - transakcja NIE jest wycofywana, więc wysłanie emaila z linkiem odblokowania zostaje zachowane
- **Odwołanie transakcji**: **NIE** (noRollbackFor w `login()`)


#### 6.2 `ExcessiveLoginAttemptsException`

- **Miejsca zgłoszenia**: `AccountService.login()`
- **Klucz internacjonalizacji**: `excessive_login_attempts`
- **Kod błędu HTTP**: 429
- **Możliwe przyczyny wystąpienia**: Przekroczenie maksymalnej liczby nieudanych prób logowania (konfigurowane przez `${app.login.maxAttempts}`)
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie + noRollbackFor** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 429 z wiadomością z klucza `excessive_login_attempts`. **UWAGA**: `noRollbackFor` w metodzie `login()` - transakcja NIE jest wycofywana, więc zablokowanie konta i zresetowanie licznika prób zostaje zachowane
- **Odwołanie transakcji**: **NIE** (noRollbackFor w `login()`)


#### 6.3 `NoAssignedDieticianException`

- **Miejsca zgłoszenia**: `ClientModService.submitPermanentSurvey()`
- **Klucz internacjonalizacji**: `no_assigned_dietican`
- **Kod błędu HTTP**: 422
- **Możliwe przyczyny wystąpienia**: Próba przesłania ankiety stałej przez klienta bez przypisanego dietetyka
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 422 z wiadomością z klucza `no_assigned_dietican`
- **Odwołanie transakcji**: Tak


#### 6.4 `DieticianClientLimitExceededException`

- **Miejsca zgłoszenia**: `ClientModService.assignDietician()`
- **Klucz internacjonalizacji**: `dietician_client_limit_exceeded`
- **Kod błędu HTTP**: 422
- **Możliwe przyczyny wystąpienia**: Próba przypisania dietetyka, który osiągnął maksymalną liczbę klientów (konfigurowane przez `${clients.max_clients}`)
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 422 z wiadomością z klucza `dietician_client_limit_exceeded`
- **Odwołanie transakcji**: Tak


#### 6.5 `ClientHasNoAssignedDieticianException`

- **Miejsca zgłoszenia**: `DieticianModService.orderMedicalExaminations()`, `DieticianModService.getDieticiansClientById()`
- **Klucz internacjonalizacji**: `client_has_no_assigned_dietician`
- **Kod błędu HTTP**: 422
- **Możliwe przyczyny wystąpienia**: Próba zlecenia badań dla klienta bez przypisanego dietetyka
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 422 z wiadomością z klucza `client_has_no_assigned_dietician`
- **Odwołanie transakcji**: Tak


#### 6.6 `ClientNotAssignedException`

- **Miejsca zgłoszenia**: Różne operacje dietetyka na klientach
- **Klucz internacjonalizacji**: `client_not_assigned`
- **Kod błędu HTTP**: 422
- **Możliwe przyczyny wystąpienia**: Próba wykonania operacji na kliencie nieprzypisanym do danego dietetyka
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 422 z wiadomością z klucza `client_not_assigned`
- **Odwołanie transakcji**: Tak


### 7. Wyjątki systemowe i EJB

#### 7.1 Wyjątki integralności danych

##### 7.1.1 `DataIntegrityViolationException`

- **Miejsca wystąpienia**: Operacje zapisu naruszające ograniczenia bazy danych
- **Klucz internacjonalizacji**: Brak (wyjątek systemowy)
- **Kod błędu HTTP**: 409
- **Możliwe przyczyny wystąpienia**: Naruszenie unique constraints, foreign key constraints, not null constraints
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Specjalny handler** - `GeneralControllerExceptionHandler.handleDataIntegrityViolationException()` analizuje przyczynę i zwraca: dla `account_login_key` → `"Constraint error: this login is already in use"`, dla `account_email_key` → `"Constraint error: this email is already in use"`, dla innych → `"A data integrity error occurred: " + ex.getMessage()`
- **Odwołanie transakcji**: Tak


##### 7.1.2 `AccountConstraintViolationException`

- **Miejsca wystąpienia**: `AdminService.createAdmin(), ClientService.createClient(), DieticianService.createDietician()`
- **Klucz internacjonalizacji**: `account_constraint_violation`
- **Kod błędu HTTP**: 409
- **Możliwe przyczyny wystąpienia**: Próba utworzenia konta z już istniejącym loginem lub emailem
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Interceptor AOP** - `AccountConstraintViolationsHandlingInterceptor` przechwytuje `DataIntegrityViolationException` i przekształca w `AccountConstraintViolationException`, następnie **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 409 z wiadomością z klucza `account_constraint_violation`
- **Odwołanie transakcji**: Tak


#### 7.2 Wyjątki blokad optymistycznych

##### 7.2.1 `OptimisticLockingFailureException`

- **Miejsca wystąpienia**: Operacje na encjach z `@Version` przy jednoczesnej modyfikacji
- **Klucz internacjonalizacji**: Brak (wyjątek systemowy)
- **Kod błędu HTTP**: 409
- **Możliwe przyczyny wystąpienia**: Jednoczesna modyfikacja tego samego zasobu przez różnych użytkowników na poziomie JPA
- **Blokady optymistyczne**: **TAK** - wyjątek JPA związany z mechanizmem `@Version`
- **Sposób obsługi**: **Interceptor AOP** - `GenericOptimisticLockHandlingInterceptor.handleOptimisticLockException()` przechwytuje wyjątek i rzuca `ConcurrentUpdateException`, który jest następnie obsługiwany przez mechanizm retry
- **Odwołanie transakcji**: Tak


#### 7.3 Wyjątki walidacyjne

##### 7.3.1 `ConstraintViolationException`

- **Miejsca wystąpienia**: Walidacja Bean Validation na poziomie metod
- **Klucz internacjonalizacji**: Brak (wyjątek systemowy)
- **Kod błędu HTTP**: 400
- **Możliwe przyczyny wystąpienia**: Naruszenie ograniczeń walidacyjnych na argumentach metod
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Specjalny handler** - `GeneralControllerExceptionHandler.onConstraintValidationException()` tworzy JSON z listą naruszeń: `{"violations": [{"field": "fieldName", "message": "error message"}]}` i zwraca HTTP 400
- **Odwołanie transakcji**: Tak


##### 7.3.2 `MethodArgumentNotValidException`

- **Miejsca wystąpienia**: Walidacja Bean Validation na argumentach metod kontrolera
- **Klucz internacjonalizacji**: Brak (wyjątek systemowy)
- **Kod błędu HTTP**: 400
- **Możliwe przyczyny wystąpienia**: Niepoprawne dane w body żądania HTTP
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Specjalny handler** - `GeneralControllerExceptionHandler.handleMethodArgumentNotValid()` tworzy JSON z listą błędów walidacji: `{"violations": [{"field": "fieldName", "message": "error message"}]}` i zwraca HTTP 400
- **Odwołanie transakcji**: Tak


##### 7.3.3 `MethodArgumentTypeMismatchException`

- **Miejsca wystąpienia**: Niepoprawny typ argumentu w URL
- **Klucz internacjonalizacji**: Brak (wyjątek systemowy)
- **Kod błędu HTTP**: 400
- **Możliwe przyczyny wystąpienia**: Niepoprawny typ argumentu w URL
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Specjalny handler** - `GeneralControllerExceptionHandler.handleMethodArgumentTypeMismatch()` tworzy JSON: `{"violations": [{"field": "paramName", "message": "Invalid value 'invalidValue' for parameter 'paramName'. Expected 'ExpectedType' type."}]}` i zwraca HTTP 400
- **Odwołanie transakcji**: Tak


##### 7.3.4 `HttpMessageNotReadableException`

- **Miejsca wystąpienia**: Nieparsowalne JSON w ciele żądania
- **Klucz internacjonalizacji**: Brak (wyjątek systemowy)
- **Kod błędu HTTP**: 400
- **Możliwe przyczyny wystąpienia**: Nieparsowalne JSON w ciele żądania HTTP
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Specjalny handler** - `GeneralControllerExceptionHandler.handleException()` zwraca pusty response z HTTP 400
- **Odwołanie transakcji**: Tak


#### 7.4 Wyjątki autoryzacji i inne systemowe

##### 7.4.1 `PersistenceException`

- **Miejsca wystąpienia**: Błędy na poziomie JPA/Hibernate
- **Klucz internacjonalizacji**: Brak (wyjątek systemowy)
- **Kod błędu HTTP**: 409
- **Możliwe przyczyny wystąpienia**: Błędy na poziomie JPA/Hibernate
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Specjalny handler** - `GeneralControllerExceptionHandler.handlePersistenceException()` zwraca `ResponseEntity.status(409).body("Persistence exception: " + ex.getMessage())`
- **Odwołanie transakcji**: Tak


##### 7.4.2 `UnknownFilterException`

- **Miejsca wystąpienia**: `JwtAuthFilter`
- **Klucz internacjonalizacji**: `unknown_filter_exception`
- **Kod błędu HTTP**: 401
- **Możliwe przyczyny wystąpienia**: Błędy w filtrach autoryzacji
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Specjalny handler** - `GeneralControllerExceptionHandler.handleTokenNotFoundException()` zwraca `ResponseEntity.status(401).body("Unknown authorization exception: " + ex.getMessage())`
- **Odwołanie transakcji**: Tak

##### 7.4.2 `MissingHttpRequestException`

- **Miejsca wystąpienia**: `MiscellaneousUtil`
- **Klucz internacjonalizacji**: `no_active_HTTP_request_context`
- **Kod błędu HTTP**: 500
- **Możliwe przyczyny wystąpienia**: Wywołanie metody wymagającej aktywnego kontekstu HTTP w miejscu, gdzie nie jest dostępny
- **Blokady optymistyczne**: Nie dotyczy
- **Sposób obsługi**: **Spring automatycznie** - Wyjątek przepuszczany przez `GeneralControllerExceptionHandler.passThroughAppExceptions()` → Spring zwraca HTTP 500 z wiadomością z klucza `no_active_HTTP_request_context`
- **Odwołanie transakcji**: Tak

### Specjalne mechanizmy obsługi

#### 1. Mechanizm `noRollbackFor` w metodzie `login()`

```java
@Transactional(
    propagation = Propagation.REQUIRES_NEW, 
    readOnly = false, 
    transactionManager = "mokTransactionManager", 
    timeoutString = "${transaction.timeout}",
    noRollbackFor = {
        InvalidCredentialsException.class, 
        ExcessiveLoginAttemptsException.class, 
        AccountIsAutolockedException.class
    }
)
public SensitiveDTO login(String username, SensitiveDTO password, String ipAddress, HttpServletResponse response) {
    
}
```

**Cel**: Umożliwienie zapisania informacji o nieudanych próbach logowania i mechanizmach bezpieczeństwa bez utraty tych danych przy wyjątkach.

#### 2. Mechanizm retry dla blokad optymistycznych

```java
@Retryable(
    retryFor = {JpaSystemException.class, ConcurrentUpdateException.class}, 
    backoff = @Backoff(delayExpression = "${app.retry.backoff}"), 
    maxAttemptsExpression = "${app.retry.maxattempts}"
)
```

**Konfiguracja** (application.properties):

```plaintext
app.retry.backoff=1000
app.retry.maxattempts=3
```

**Działanie**:

1. Pierwsza próba wykonania metody
2. Jeśli wystąpi `ConcurrentUpdateException` → czekaj 1000ms i spróbuj ponownie
3. Maksymalnie 3 próby
4. Po wyczerpaniu prób → wyjątek trafia do Spring i zwraca HTTP 409


#### 3. Interceptor dla blokad optymistycznych

```java
@AfterThrowing(pointcut = "Pointcuts.allRepositoryMethods()", throwing = "olfe")
public void handleOptimisticLockException(JoinPoint joinPoint, OptimisticLockingFailureException olfe) {
    throw new ConcurrentUpdateException(olfe);
}
```

**Działanie**: Przechwytuje `OptimisticLockingFailureException` z warstwy JPA i przekształca w `ConcurrentUpdateException` aplikacyjny.

#### 4. Podstawowy mechanizm dla wyjątków aplikacyjnych

```java
@ExceptionHandler(AppBaseException.class)
public void passThroughAppExceptions(
        AppBaseException exception,
        WebRequest request
){
    throw exception;
}
```

**Działanie**: Wszystkie wyjątki aplikacyjne dziedziczą po `AppBaseException` → `ResponseStatusException`, więc Spring automatycznie wyciąga kod HTTP i wiadomość z wyjątku i zwraca odpowiedź HTTP.

#### 5. Interceptor dla ograniczeń kont

```java
@AfterThrowing(pointcut = "Pointcuts.allAccountServiceMethods()", throwing = "dive")
public void handleAccountConstraintViolations(JoinPoint joinPoint, DataIntegrityViolationException dive) {
    throw new AccountConstraintViolationException(dive);
}
```

**Działanie**:

- Przechwytuje `DataIntegrityViolationException` w metodach `AccountService`
- Przekształca w `AccountConstraintViolationException` aplikacyjny


// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//go:build !wireinject
// +build !wireinject

package main

import (
	"context"

	check2 "github.com/harness/gitness/app/api/controller/check"
	"github.com/harness/gitness/app/api/controller/connector"
	"github.com/harness/gitness/app/api/controller/execution"
	keywordsearch2 "github.com/harness/gitness/app/api/controller/keywordsearch"
	"github.com/harness/gitness/app/api/controller/limiter"
	logs2 "github.com/harness/gitness/app/api/controller/logs"
	"github.com/harness/gitness/app/api/controller/pipeline"
	"github.com/harness/gitness/app/api/controller/plugin"
	"github.com/harness/gitness/app/api/controller/principal"
	pullreq2 "github.com/harness/gitness/app/api/controller/pullreq"
	"github.com/harness/gitness/app/api/controller/repo"
	"github.com/harness/gitness/app/api/controller/secret"
	"github.com/harness/gitness/app/api/controller/service"
	"github.com/harness/gitness/app/api/controller/serviceaccount"
	"github.com/harness/gitness/app/api/controller/space"
	"github.com/harness/gitness/app/api/controller/system"
	"github.com/harness/gitness/app/api/controller/template"
	"github.com/harness/gitness/app/api/controller/trigger"
	"github.com/harness/gitness/app/api/controller/upload"
	"github.com/harness/gitness/app/api/controller/user"
	webhook2 "github.com/harness/gitness/app/api/controller/webhook"
	"github.com/harness/gitness/app/api/openapi"
	"github.com/harness/gitness/app/auth/authn"
	"github.com/harness/gitness/app/auth/authz"
	"github.com/harness/gitness/app/bootstrap"
	events4 "github.com/harness/gitness/app/events/git"
	events3 "github.com/harness/gitness/app/events/pullreq"
	events2 "github.com/harness/gitness/app/events/repo"
	"github.com/harness/gitness/app/githook"
	"github.com/harness/gitness/app/pipeline/canceler"
	"github.com/harness/gitness/app/pipeline/commit"
	"github.com/harness/gitness/app/pipeline/converter"
	"github.com/harness/gitness/app/pipeline/file"
	"github.com/harness/gitness/app/pipeline/manager"
	"github.com/harness/gitness/app/pipeline/resolver"
	"github.com/harness/gitness/app/pipeline/runner"
	"github.com/harness/gitness/app/pipeline/scheduler"
	"github.com/harness/gitness/app/pipeline/triggerer"
	"github.com/harness/gitness/app/router"
	server2 "github.com/harness/gitness/app/server"
	"github.com/harness/gitness/app/services"
	"github.com/harness/gitness/app/services/cleanup"
	"github.com/harness/gitness/app/services/codecomments"
	"github.com/harness/gitness/app/services/codeowners"
	"github.com/harness/gitness/app/services/exporter"
	"github.com/harness/gitness/app/services/importer"
	"github.com/harness/gitness/app/services/keywordsearch"
	"github.com/harness/gitness/app/services/metric"
	"github.com/harness/gitness/app/services/notification"
	"github.com/harness/gitness/app/services/notification/mailer"
	"github.com/harness/gitness/app/services/protection"
	"github.com/harness/gitness/app/services/pullreq"
	"github.com/harness/gitness/app/services/reposize"
	trigger2 "github.com/harness/gitness/app/services/trigger"
	"github.com/harness/gitness/app/services/usergroup"
	"github.com/harness/gitness/app/services/webhook"
	"github.com/harness/gitness/app/sse"
	"github.com/harness/gitness/app/store"
	"github.com/harness/gitness/app/store/cache"
	"github.com/harness/gitness/app/store/database"
	"github.com/harness/gitness/app/store/logs"
	"github.com/harness/gitness/app/url"
	"github.com/harness/gitness/blob"
	"github.com/harness/gitness/cli/operations/server"
	"github.com/harness/gitness/encrypt"
	"github.com/harness/gitness/events"
	"github.com/harness/gitness/git"
	"github.com/harness/gitness/git/api"
	"github.com/harness/gitness/git/storage"
	"github.com/harness/gitness/job"
	"github.com/harness/gitness/livelog"
	"github.com/harness/gitness/lock"
	"github.com/harness/gitness/pubsub"
	"github.com/harness/gitness/store/database/dbtx"
	"github.com/harness/gitness/types"
	"github.com/harness/gitness/types/check"

	_ "github.com/lib/pq"

	_ "github.com/mattn/go-sqlite3"
)

// Injectors from wire.go:

func initSystem(ctx context.Context, config *types.Config) (*server.System, error) {
	databaseConfig := server.ProvideDatabaseConfig(config)
	db, err := database.ProvideDatabase(ctx, databaseConfig)
	if err != nil {
		return nil, err
	}
	accessorTx := dbtx.ProvideAccessorTx(db)
	transactor := dbtx.ProvideTransactor(accessorTx)
	principalUID := check.ProvidePrincipalUIDCheck()
	spacePathTransformation := store.ProvidePathTransformation()
	spacePathStore := database.ProvideSpacePathStore(db, spacePathTransformation)
	spacePathCache := cache.ProvidePathCache(spacePathStore, spacePathTransformation)
	spaceStore := database.ProvideSpaceStore(db, spacePathCache, spacePathStore)
	principalInfoView := database.ProvidePrincipalInfoView(db)
	principalInfoCache := cache.ProvidePrincipalInfoCache(principalInfoView)
	membershipStore := database.ProvideMembershipStore(db, principalInfoCache, spacePathStore, spaceStore)
	permissionCache := authz.ProvidePermissionCache(spaceStore, membershipStore)
	authorizer := authz.ProvideAuthorizer(permissionCache, spaceStore)
	principalUIDTransformation := store.ProvidePrincipalUIDTransformation()
	principalStore := database.ProvidePrincipalStore(db, principalUIDTransformation)
	tokenStore := database.ProvideTokenStore(db)
	controller := user.ProvideController(transactor, principalUID, authorizer, principalStore, tokenStore, membershipStore)
	serviceController := service.NewController(principalUID, authorizer, principalStore)
	bootstrapBootstrap := bootstrap.ProvideBootstrap(config, controller, serviceController)
	authenticator := authn.ProvideAuthenticator(config, principalStore, tokenStore)
	provider, err := url.ProvideURLProvider(config)
	if err != nil {
		return nil, err
	}
	repoStore := database.ProvideRepoStore(db, spacePathCache, spacePathStore, spaceStore)
	pipelineStore := database.ProvidePipelineStore(db)
	ruleStore := database.ProvideRuleStore(db, principalInfoCache)
	protectionManager, err := protection.ProvideManager(ruleStore)
	if err != nil {
		return nil, err
	}
	typesConfig := server.ProvideGitConfig(config)
	universalClient, err := server.ProvideRedis(config)
	if err != nil {
		return nil, err
	}
	cacheCache, err := api.ProvideLastCommitCache(typesConfig, universalClient)
	if err != nil {
		return nil, err
	}
	clientFactory := githook.ProvideFactory()
	apiGit, err := git.ProvideGITAdapter(typesConfig, cacheCache, clientFactory)
	if err != nil {
		return nil, err
	}
	storageStore := storage.ProvideLocalStore()
	gitInterface, err := git.ProvideService(typesConfig, apiGit, storageStore)
	if err != nil {
		return nil, err
	}
	triggerStore := database.ProvideTriggerStore(db)
	encrypter, err := encrypt.ProvideEncrypter(config)
	if err != nil {
		return nil, err
	}
	jobStore := database.ProvideJobStore(db)
	pubsubConfig := server.ProvidePubsubConfig(config)
	pubSub := pubsub.ProvidePubSub(pubsubConfig, universalClient)
	executor := job.ProvideExecutor(jobStore, pubSub)
	lockConfig := server.ProvideLockConfig(config)
	mutexManager := lock.ProvideMutexManager(lockConfig, universalClient)
	jobConfig := server.ProvideJobsConfig(config)
	jobScheduler, err := job.ProvideScheduler(jobStore, executor, mutexManager, pubSub, jobConfig)
	if err != nil {
		return nil, err
	}
	streamer := sse.ProvideEventsStreaming(pubSub)
	localIndexSearcher := keywordsearch.ProvideLocalIndexSearcher()
	indexer := keywordsearch.ProvideIndexer(localIndexSearcher)
	repository, err := importer.ProvideRepoImporter(config, provider, gitInterface, transactor, repoStore, pipelineStore, triggerStore, encrypter, jobScheduler, executor, streamer, indexer)
	if err != nil {
		return nil, err
	}
	codeownersConfig := server.ProvideCodeOwnerConfig(config)
	usergroupResolver := usergroup.ProvideUserGroupResolver()
	codeownersService := codeowners.ProvideCodeOwners(gitInterface, repoStore, codeownersConfig, principalStore, usergroupResolver)
	eventsConfig := server.ProvideEventsConfig(config)
	eventsSystem, err := events.ProvideSystem(eventsConfig, universalClient)
	if err != nil {
		return nil, err
	}
	reporter, err := events2.ProvideReporter(eventsSystem)
	if err != nil {
		return nil, err
	}
	resourceLimiter, err := limiter.ProvideLimiter()
	if err != nil {
		return nil, err
	}
	repoIdentifier := check.ProvideRepoIdentifierCheck()
	repoController := repo.ProvideController(config, transactor, provider, authorizer, repoStore, spaceStore, pipelineStore, principalStore, ruleStore, principalInfoCache, protectionManager, gitInterface, repository, codeownersService, reporter, indexer, resourceLimiter, mutexManager, repoIdentifier)
	executionStore := database.ProvideExecutionStore(db)
	checkStore := database.ProvideCheckStore(db, principalInfoCache)
	stageStore := database.ProvideStageStore(db)
	schedulerScheduler, err := scheduler.ProvideScheduler(stageStore, mutexManager)
	if err != nil {
		return nil, err
	}
	stepStore := database.ProvideStepStore(db)
	cancelerCanceler := canceler.ProvideCanceler(executionStore, streamer, repoStore, schedulerScheduler, stageStore, stepStore)
	commitService := commit.ProvideService(gitInterface)
	fileService := file.ProvideService(gitInterface)
	converterService := converter.ProvideService(fileService)
	templateStore := database.ProvideTemplateStore(db)
	pluginStore := database.ProvidePluginStore(db)
	triggererTriggerer := triggerer.ProvideTriggerer(executionStore, checkStore, stageStore, transactor, pipelineStore, fileService, converterService, schedulerScheduler, repoStore, provider, templateStore, pluginStore)
	executionController := execution.ProvideController(transactor, authorizer, executionStore, checkStore, cancelerCanceler, commitService, triggererTriggerer, repoStore, stageStore, pipelineStore)
	logStore := logs.ProvideLogStore(db, config)
	logStream := livelog.ProvideLogStream()
	logsController := logs2.ProvideController(authorizer, executionStore, repoStore, pipelineStore, stageStore, stepStore, logStore, logStream)
	spaceIdentifier := check.ProvideSpaceIdentifierCheck()
	secretStore := database.ProvideSecretStore(db)
	connectorStore := database.ProvideConnectorStore(db)
	exporterRepository, err := exporter.ProvideSpaceExporter(provider, gitInterface, repoStore, jobScheduler, executor, encrypter, streamer)
	if err != nil {
		return nil, err
	}
	spaceController := space.ProvideController(config, transactor, provider, streamer, spaceIdentifier, authorizer, spacePathStore, pipelineStore, secretStore, connectorStore, templateStore, spaceStore, repoStore, principalStore, repoController, membershipStore, repository, exporterRepository, resourceLimiter)
	pipelineController := pipeline.ProvideController(repoStore, triggerStore, authorizer, pipelineStore)
	secretController := secret.ProvideController(encrypter, secretStore, authorizer, spaceStore)
	triggerController := trigger.ProvideController(authorizer, triggerStore, pipelineStore, repoStore)
	connectorController := connector.ProvideController(connectorStore, authorizer, spaceStore)
	templateController := template.ProvideController(templateStore, authorizer, spaceStore)
	pluginController := plugin.ProvideController(pluginStore)
	pullReqStore := database.ProvidePullReqStore(db, principalInfoCache)
	pullReqActivityStore := database.ProvidePullReqActivityStore(db, principalInfoCache)
	codeCommentView := database.ProvideCodeCommentView(db)
	pullReqReviewStore := database.ProvidePullReqReviewStore(db)
	pullReqReviewerStore := database.ProvidePullReqReviewerStore(db, principalInfoCache)
	pullReqFileViewStore := database.ProvidePullReqFileViewStore(db)
	eventsReporter, err := events3.ProvideReporter(eventsSystem)
	if err != nil {
		return nil, err
	}
	migrator := codecomments.ProvideMigrator(gitInterface)
	readerFactory, err := events4.ProvideReaderFactory(eventsSystem)
	if err != nil {
		return nil, err
	}
	eventsReaderFactory, err := events3.ProvideReaderFactory(eventsSystem)
	if err != nil {
		return nil, err
	}
	repoGitInfoView := database.ProvideRepoGitInfoView(db)
	repoGitInfoCache := cache.ProvideRepoGitInfoCache(repoGitInfoView)
	pullreqService, err := pullreq.ProvideService(ctx, config, readerFactory, eventsReaderFactory, eventsReporter, gitInterface, repoGitInfoCache, repoStore, pullReqStore, pullReqActivityStore, codeCommentView, migrator, pullReqFileViewStore, pubSub, provider, streamer)
	if err != nil {
		return nil, err
	}
	pullreqController := pullreq2.ProvideController(transactor, provider, authorizer, pullReqStore, pullReqActivityStore, codeCommentView, pullReqReviewStore, pullReqReviewerStore, repoStore, principalStore, pullReqFileViewStore, membershipStore, checkStore, gitInterface, eventsReporter, mutexManager, migrator, pullreqService, protectionManager, streamer, codeownersService)
	webhookConfig := server.ProvideWebhookConfig(config)
	webhookStore := database.ProvideWebhookStore(db)
	webhookExecutionStore := database.ProvideWebhookExecutionStore(db)
	webhookService, err := webhook.ProvideService(ctx, webhookConfig, readerFactory, eventsReaderFactory, webhookStore, webhookExecutionStore, repoStore, pullReqStore, pullReqActivityStore, provider, principalStore, gitInterface, encrypter)
	if err != nil {
		return nil, err
	}
	webhookController := webhook2.ProvideController(webhookConfig, authorizer, webhookStore, webhookExecutionStore, repoStore, webhookService, encrypter)
	reporter2, err := events4.ProvideReporter(eventsSystem)
	if err != nil {
		return nil, err
	}
	githookController := githook.ProvideController(authorizer, principalStore, repoStore, reporter2, gitInterface, pullReqStore, provider, protectionManager, clientFactory, resourceLimiter)
	serviceaccountController := serviceaccount.NewController(principalUID, authorizer, principalStore, spaceStore, repoStore, tokenStore)
	principalController := principal.ProvideController(principalStore)
	v := check2.ProvideCheckSanitizers()
	checkController := check2.ProvideController(transactor, authorizer, repoStore, checkStore, gitInterface, v)
	systemController := system.NewController(principalStore, config)
	blobConfig, err := server.ProvideBlobStoreConfig(config)
	if err != nil {
		return nil, err
	}
	blobStore, err := blob.ProvideStore(ctx, blobConfig)
	if err != nil {
		return nil, err
	}
	uploadController := upload.ProvideController(authorizer, repoStore, blobStore)
	searcher := keywordsearch.ProvideSearcher(localIndexSearcher)
	keywordsearchController := keywordsearch2.ProvideController(authorizer, searcher, repoController, spaceController)
	apiHandler := router.ProvideAPIHandler(ctx, config, authenticator, repoController, executionController, logsController, spaceController, pipelineController, secretController, triggerController, connectorController, templateController, pluginController, pullreqController, webhookController, githookController, serviceaccountController, controller, principalController, checkController, systemController, uploadController, keywordsearchController)
	gitHandler := router.ProvideGitHandler(provider, authenticator, repoController)
	openapiService := openapi.ProvideOpenAPIService()
	webHandler := router.ProvideWebHandler(config, openapiService)
	routerRouter := router.ProvideRouter(apiHandler, gitHandler, webHandler, provider)
	serverServer := server2.ProvideServer(config, routerRouter)
	executionManager := manager.ProvideExecutionManager(config, executionStore, pipelineStore, provider, streamer, fileService, converterService, logStore, logStream, checkStore, repoStore, schedulerScheduler, secretStore, stageStore, stepStore, principalStore)
	client := manager.ProvideExecutionClient(executionManager, provider, config)
	resolverManager := resolver.ProvideResolver(config, pluginStore, templateStore, executionStore, repoStore)
	runtimeRunner, err := runner.ProvideExecutionRunner(config, client, resolverManager)
	if err != nil {
		return nil, err
	}
	poller := runner.ProvideExecutionPoller(runtimeRunner, client)
	triggerConfig := server.ProvideTriggerConfig(config)
	triggerService, err := trigger2.ProvideService(ctx, triggerConfig, triggerStore, commitService, pullReqStore, repoStore, pipelineStore, triggererTriggerer, readerFactory, eventsReaderFactory)
	if err != nil {
		return nil, err
	}
	collector, err := metric.ProvideCollector(config, principalStore, repoStore, pipelineStore, executionStore, jobScheduler, executor)
	if err != nil {
		return nil, err
	}
	calculator, err := reposize.ProvideCalculator(config, gitInterface, repoStore, jobScheduler, executor)
	if err != nil {
		return nil, err
	}
	cleanupConfig := server.ProvideCleanupConfig(config)
	cleanupService, err := cleanup.ProvideService(cleanupConfig, jobScheduler, executor, webhookExecutionStore, tokenStore, repoStore, repoController)
	if err != nil {
		return nil, err
	}
	mailerMailer := mailer.ProvideMailClient(config)
	notificationClient := notification.ProvideMailClient(mailerMailer)
	notificationConfig := server.ProvideNotificationConfig(config)
	notificationService, err := notification.ProvideNotificationService(ctx, notificationClient, notificationConfig, eventsReaderFactory, pullReqStore, repoStore, principalInfoView, principalInfoCache, pullReqReviewerStore, pullReqActivityStore, spacePathStore, provider)
	if err != nil {
		return nil, err
	}
	keywordsearchConfig := server.ProvideKeywordSearchConfig(config)
	keywordsearchService, err := keywordsearch.ProvideService(ctx, keywordsearchConfig, readerFactory, repoStore, indexer)
	if err != nil {
		return nil, err
	}
	servicesServices := services.ProvideServices(webhookService, pullreqService, triggerService, jobScheduler, collector, calculator, cleanupService, notificationService, keywordsearchService)
	serverSystem := server.NewSystem(bootstrapBootstrap, serverServer, poller, resolverManager, servicesServices)
	return serverSystem, nil
}

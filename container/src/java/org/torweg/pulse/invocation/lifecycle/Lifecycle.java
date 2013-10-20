/*
 * Copyright 2005 :torweg free software group
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */
package org.torweg.pulse.invocation.lifecycle;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.apache.fop.apps.FopFactory;
import org.apache.log4j.NDC;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.torweg.pulse.annotations.Action.Security;
import org.torweg.pulse.bundle.Bundle;
import org.torweg.pulse.bundle.JobletScheduler;
import org.torweg.pulse.component.Component;
import org.torweg.pulse.configuration.Configuration;
import org.torweg.pulse.configuration.PoorMansCache;
import org.torweg.pulse.email.MailQueue;
import org.torweg.pulse.email.MailQueueConfiguration;
import org.torweg.pulse.service.PulseConfig;
import org.torweg.pulse.service.request.ApplicationLocale;
import org.torweg.pulse.service.request.LocaleManager;
import org.torweg.pulse.service.request.SystemLocale;
import org.torweg.pulse.util.HibernateDataSource;
import org.torweg.pulse.util.HibernateDataSourceImpl;
import org.torweg.pulse.util.captcha.ICaptchaAdapter;
import org.torweg.pulse.util.geolocation.IGeoLocationProvider;
import org.torweg.pulse.util.geolocation.NoLookupLocationProvider;
import org.torweg.pulse.util.time.MillisecondConstant;
import org.torweg.pulse.util.time.TimeSpan;
import org.torweg.pulse.vfs.VirtualFileSystem;

import com.sun.jersey.api.json.JSONJAXBContext;

/**
 * initialises all bundles and manages the life-cycle of reloadable components.
 * <p>
 * The {@code Lifecycle} singleton initialises all bundles of the <em>pulse</em>
 * container and the config pool. If the container is configured for reloading
 * the {@code Lifecycle} singleton watches registered resources for changes and
 * restarts the affected sub-systems on demand.
 * </p>
 * <p>
 * Moreover it globally initialises the {@code HibernateDataSource}, all
 * {@code Bundle}s and their resources as well as the {@code ContentRegistry}
 * and {@code Sitemap}.
 * </p>
 * <p>
 * The {@code Lifecycle} sets up a global JAXB context, registers the
 * {@code IP2CountryProvider} and sets up the {@code MailQueue} as well as the
 * {@code VirtualFileSystem}.
 * </p>
 * 
 * @author Thomas Weber, Christian Schatt
 * @version $Revision: 3094 $
 * @see PoorMansCache
 * @see Bundle
 * @see org.torweg.pulse.util.HibernateDataSource
 * @see org.torweg.pulse.site.content.ContentRegistry
 */
public final class Lifecycle {

	/**
	 * the logger.
	 */
	private static final Logger LOGGER = LoggerFactory
			.getLogger(Lifecycle.class);

	/**
	 * the singleton itself.
	 */
	private static Lifecycle lifecycleInstance;

	/**
	 * the default random source (usually a {@code SecureRandom}).
	 */
	private static SecureRandom random;

	/**
	 * timestamp of the last seeding of the {@code random}.
	 */
	private static long lastRandomSeeding;

	/**
	 * the root directory of the <em>pulse</em> webapp.
	 */
	private final File pulseRootDir;

	/**
	 * the config directory for the <em>pulse</em> core.
	 */
	private final File coreConfigDir;

	/**
	 * the root directory for all bundles.
	 */
	private final File bundlesRootDir;

	/**
	 * the bundles.
	 */
	private final ConcurrentHashMap<String, Bundle> bundles = new ConcurrentHashMap<String, Bundle>();

	/**
	 * the components.
	 */
	private final Set<Component> components = new HashSet<Component>();

	/**
	 * the Timer for the WatchDog.
	 */
	private Timer timer;

	/**
	 * The HibernateDataSource for this Lifecycle.
	 */
	private HibernateDataSourceImpl hibernateDataSource;

	/**
	 * The locales known to the installation - for sitemap and content-registry.
	 */
	private Collection<ApplicationLocale> applicationLocales;

	/**
	 * The additional system locales known to the installation.
	 */
	private Collection<SystemLocale> systemLocales;

	/**
	 * the global {@code JAXBContext}.
	 */
	private JAXBContext jaxbContext;

	/**
	 * the {@code MailQueue}.
	 */
	private MailQueue mailQueue;

	/**
	 * the ip to country lookup provider.
	 */
	private IGeoLocationProvider geoLocationProvider;

	/**
	 * The {@code ICaptchaAdapter} if configured, {@code null} otherwise.
	 */
	private ICaptchaAdapter<?> captchaAdapter;

	/**
	 * the watch dog.
	 */
	private WatchDog watchDog;

	/**
	 * The {@code FopFactory}-instance.
	 */
	private FopFactory fopFactoryInstance;

	/**
	 * the JSON JAXB context.
	 */
	private JSONJAXBContext jsonJaxbContext;

	/**
	 * the salt to be used for creating salted hashes.
	 * 
	 * @see Lifecycle#getSaltedHash(byte[])
	 */
	private byte[] serverSalt;
	
	/**
	 * configuration file to use
	 * 
	 * changes when unit-testing
	 */
	private String configurationFile;

	/**
	 * private constructor for the singleton.
	 * 
	 * @param pulseWebapp
	 *            the root directory of the <em>pulse</em> webapp
	 */
	private Lifecycle(final File pulseWebapp) {
		this.pulseRootDir = pulseWebapp;
		this.coreConfigDir = new File(this.pulseRootDir, "WEB-INF"
				+ File.separator + "conf");
		this.bundlesRootDir = new File(pulseWebapp, "WEB-INF" + File.separator
				+ "bundles");
	}

	/**
	 * @return the bundles of the <em>pulse</em> container
	 */
	public static Collection<Bundle> getBundles() {
		if (lifecycleInstance != null) {
			return lifecycleInstance.bundles.values();
		}
		throw new LifecycleException("The Lifecycle has not been started.");
	}

	/**
	 * get the Bundle with the specified name.
	 * 
	 * @param name
	 *            the name of the bundle
	 * @return the Bundle
	 * @throws BundleNotFoundException
	 *             if the named bundle cannot be found
	 */
	public static Bundle getBundle(final String name) {
		if (lifecycleInstance != null) {
			Bundle b = lifecycleInstance.bundles.get(name);
			if (b != null) {
				return b;
			}
			throw new BundleNotFoundException(name);
		}
		throw new LifecycleException("The Lifecycle has not been started.");
	}

	/* --- START: protected direct access methods for Lifecycle tasks --------- */

	/**
	 * returns the containers root directory.
	 * 
	 * @return the containers root directory
	 */
	public static File getBasePath() {
		if (lifecycleInstance != null) {
			return lifecycleInstance.pulseRootDir.getAbsoluteFile();
		}
		throw new LifecycleException("The Lifecycle has not been started.");
	}

	/**
	 * Returns the {@code HibernateDataSource}.
	 * 
	 * @return the {@code HibernateDataSource}
	 */
	public static HibernateDataSource getHibernateDataSource() {
		if (lifecycleInstance != null) {
			return lifecycleInstance.hibernateDataSource;
		}
		throw new LifecycleException("The Lifecycle has not been started.");
	}

	/**
	 * returns the {@code IGeoLocationProvider}.
	 * 
	 * @return the {@code IGeoLocationProvider}
	 */
	public static IGeoLocationProvider getGeoLocationProvider() {
		if (lifecycleInstance != null) {
			return lifecycleInstance.geoLocationProvider;
		}
		throw new LifecycleException("The Lifecycle has not been started.");
	}

	/**
	 * Returns the (configured) {@code ICaptchaAdapter}.
	 * 
	 * @return the captcha-adapter
	 */
	public static ICaptchaAdapter<?> getCaptchaAdapter() {
		if (lifecycleInstance != null) {
			return lifecycleInstance.captchaAdapter;
		}
		throw new LifecycleException("The Lifecycle has not been started.");
	}

	/**
	 * Returns the {@code Lifecycle}s' (configured) {@code FopFactory}
	 * -instance.
	 * 
	 * @return the {@code Lifecycle}s' {@code FopFactory}-instance
	 */
	public static FopFactory getFopFactory() {
		if (lifecycleInstance != null) {
			return lifecycleInstance.fopFactoryInstance;
		}
		throw new LifecycleException("The Lifecycle has not been started.");
	}

	/**
	 * @see javax.xml.bind.JAXBContext
	 * @return the global JAXBContext
	 */
	public static JAXBContext getJAXBContext() {
		return lifecycleInstance.jaxbContext;
	}

	/**
	 * 
	 * @return a {@code JSONJAXBContext#newInstance(String)} with a JSON mapping
	 *         of {@code JSONConfiguration#Notation#NATURAL}
	 */
	public static JSONJAXBContext getJSONJAXBContext() {
		return lifecycleInstance.jsonJaxbContext;
	}

	/**
	 * returns a list of all known {@code ApplicationLocale}s as {@code Locale}
	 * s.
	 * 
	 * @return a list of all known {@code ApplicationLocale}s as {@code Locale}
	 * 
	 * @see #getActiveLocales()
	 */
	public static Collection<Locale> getKnownLocales() {
		if (lifecycleInstance != null) {
			return convertLocaleList(lifecycleInstance.applicationLocales,
					false);
		}
		throw new LifecycleException("The Lifecycle has not been started.");
	}

	/**
	 * Extracts the known languages from the known {@code ApplicationLocale}s.
	 * 
	 * @return the {@code Collection<String>} known languages
	 */
	public static Collection<String> getKnownLanguages() {
		Set<String> languages = new HashSet<String>();
		for (Locale l : getKnownLocales()) {
			languages.add(l.getLanguage());
		}
		return languages;
	}

	/**
	 * Extracts the known countries from the known {@code ApplicationLocale}s.
	 * 
	 * @return the {@code Collection<String>} known countries
	 */
	public static Collection<String> getKnownCountries() {
		Set<String> countries = new HashSet<String>();
		for (Locale l : getKnownLocales()) {
			countries.add(l.getCountry());
		}
		return countries;
	}

	/**
	 * returns a list of all active {@code {@link ApplicationLocale}s}.
	 * 
	 * @return a list of all active {@code {@link ApplicationLocale}s}
	 * @see #getKnownLocales()
	 */
	public static Collection<Locale> getActiveLocales() {
		if (lifecycleInstance != null) {
			return convertLocaleList(lifecycleInstance.applicationLocales, true);
		}
		throw new LifecycleException("The Lifecycle has not been started.");
	}

	/**
	 * Returns all {@code Locale}s known to the system - This will be all
	 * {@code Locales} as provided by {@code Locale#getAvailableLocales()}, all
	 * {@code ApplicationLocale}s and all {@code SystemLocale}s ensuring that
	 * each language-country-variant combination occurs one time only.
	 * 
	 * @return all {@code Locale}s known to the system
	 */
	public static Collection<Locale> getSystemLocales() {
		if (lifecycleInstance != null) {

			// used for filtering
			Map<String, Locale> systemLocales = new HashMap<String, Locale>();

			// add all locales as provided by Locale itself
			for (Locale locale : Locale.getAvailableLocales()) {
				systemLocales.put(locale.toString(), locale);
			}

			// add application locales
			for (Locale locale : convertLocaleList(lifecycleInstance.applicationLocales)) {
				systemLocales.put(locale.toString(), locale);
			}

			// add system locales
			for (Locale locale : convertLocaleList(lifecycleInstance.systemLocales)) {
				systemLocales.put(locale.toString(), locale);
			}

			return systemLocales.values();
		}
		throw new LifecycleException("The Lifecycle has not been started.");
	}

	/**
	 * returns the {@code MailQueue}.
	 * 
	 * @return the {@code MailQueue}
	 */
	public static MailQueue getMailQueue() {
		if (lifecycleInstance != null) {
			return lifecycleInstance.mailQueue;
		}
		throw new LifecycleException("The Lifecycle has not been started.");
	}

	/**
	 * indicates whether <em>pulse</em> is configured to use TLS.
	 * 
	 * @return {@code true}, if TLS is available
	 */
	public static boolean isTransportLayerSecurityAvailable() {
		if (lifecycleInstance != null) {
			return lifecycleInstance.getPulseConfiguration()
					.isTransportLayerSecurityAvailable();
		}
		throw new LifecycleException("The Lifecycle has not been started.");
	}

	/**
	 * returns the weakest security level {@link Security} to be honoured, if
	 * TLS is available.
	 * 
	 * @return the weakest security level to be honoured
	 * @see #isTransportLayerSecurityAvailable()
	 */
	public static Security getWeakestCommandSecurityLevel() {
		if (lifecycleInstance != null) {
			return lifecycleInstance.getPulseConfiguration()
					.getWeakestCommandSecurityLevel();
		}
		throw new LifecycleException("The Lifecycle has not been started.");
	}

	/**
	 * returns the port to be used for standard HTTP connections.
	 * 
	 * @return the port to be used for standard HTTP connections
	 */
	public static int getDefaultPort() {
		if (lifecycleInstance != null) {
			return lifecycleInstance.getPulseConfiguration().getDefaultPort();
		}
		throw new LifecycleException("The Lifecycle has not been started.");
	}

	/**
	 * returns the port to be used for secure (HTTPS) connections.
	 * 
	 * @return the port to be used for secure (HTTPS) connections
	 */
	public static int getSecurePort() {
		if (lifecycleInstance != null) {
			return lifecycleInstance.getPulseConfiguration().getSecurePort();
		}
		throw new LifecycleException("The Lifecycle has not been started.");
	}

	/**
	 * returns the versioning prefix (see:
	 * {@link org.torweg.pulse.service.VersionRewriteFilter}).
	 * 
	 * @return the versioning prefix
	 */
	public static String getVersioningPrefix() {
		if (lifecycleInstance != null) {
			return lifecycleInstance.getPulseConfiguration()
					.getVersioningPrefix();
		}
		throw new LifecycleException("The Lifecycle has not been started.");
	}

	/**
	 * returns a seeded {@code SecureRandom}.
	 * 
	 * @return the default random source
	 */
	public static SecureRandom getSecureRandom() {
		return random;
	}

	/**
	 * creates a salted SHA-512 hash of the given byte array.
	 * 
	 * @param src
	 *            the source byte array to be hashed
	 * @return a salted SHA-512 hash of the given byte array
	 * @throws NoSuchAlgorithmException
	 *             if the SHA-512 hash algorithm is not available
	 */
	public static byte[] getSaltedHash(final byte[] src)
			throws NoSuchAlgorithmException {
		if (lifecycleInstance.serverSalt.length == 0) {
			return MessageDigest.getInstance("SHA-512").digest(src);
		}
		byte[] salted = new byte[src.length
				+ lifecycleInstance.serverSalt.length];
		System.arraycopy(src, 0, salted, 0, src.length);
		System.arraycopy(lifecycleInstance.serverSalt, 0, salted, src.length,
				lifecycleInstance.serverSalt.length);
		return MessageDigest.getInstance("SHA-512").digest(salted);
	}

	/**
	 * initialises the Lifecyle singleton.
	 * 
	 * @param pulseWebapp
	 *            the root directory of the <em>pulse</em> webapp
	 */
	public static synchronized void startup(final File pulseWebapp) { // NOPMD
		if (lifecycleInstance == null) {
			Lifecycle localLifecycle = new Lifecycle(pulseWebapp);
			localLifecycle.setConfigurationFile("pulse.xml");
			lifecycleInstance = localLifecycle;
			try {
				localLifecycle.init();
			} catch (Exception e) {
				lifecycleInstance = null; // NOPMD
				throw new LifecycleException("Error while starting Lifecycle: "
						+ e.getLocalizedMessage(), e);
			}
		} else {
			throw new LifecycleException("Lifecycle has already been started.");
		}
		LOGGER.info("The Lifecycle has begun...");
	}

	/**
	 * initialises the Lifecyle singleton for unit tests.
	 * 
	 * @param pulseWebapp
	 *            the root directory of the <em>pulse</em> webapp
	 */
	public static synchronized void testStartup(final File pulseWebapp) { // NOPMD
		if (lifecycleInstance == null) {
			Lifecycle localLifecycle = new Lifecycle(pulseWebapp);
			localLifecycle.setConfigurationFile("test.xml");
			lifecycleInstance = localLifecycle;
			try {
				localLifecycle.init();
			} catch (Exception e) {
				lifecycleInstance = null; // NOPMD
				throw new LifecycleException("Error while starting Lifecycle: "
						+ e.getLocalizedMessage(), e);
			}
		} else {
			throw new LifecycleException("Lifecycle has already been started.");
		}
		LOGGER.info("The Lifecycle has begun...");
	}
	// /**
	// * @return the Lifecycle singleton
	// */
	// @Deprecated
	// public static Lifecycle getInstance() {
	// if (lifecycleInstance == null) {
	// throw new LifecycleException("Lifecycle has not been started.");
	// }
	// return lifecycleInstance;
	// }

	/**
	 * shuts the Lifecycle singleton down.
	 */
	public static synchronized void shutdown() { // NOPMD
		if (lifecycleInstance != null) {
			lifecycleInstance.destroy();
			lifecycleInstance = null; // NOPMD by thomas on 29.02.08 21:32
		} else {
			LOGGER.warn("The Lifecycle has not been started!");
		}
		LOGGER.info("The Lifecycle has stopped...");
	}

	/* --- START: protected direct access methods for Lifecycle tasks --------- */

	/**
	 * used by some Lifecycle tasks.
	 * 
	 * @return the root directory
	 */
	protected File getPulseRootDir() {
		return this.pulseRootDir;
	}

	/**
	 * used by some Lifecycle tasks.
	 * 
	 * @return the locales
	 */
	protected Collection<ApplicationLocale> getLocalesDirectly() {
		return this.applicationLocales;
	}

	/**
	 * used by some Lifecycle tasks.
	 * 
	 * @return the components
	 */
	protected Set<Component> getComponentsDirectly() {
		return this.components;
	}

	/**
	 * used by {@code LifecycleHibernateTasks}.
	 * 
	 * @return the bundles
	 */
	protected ConcurrentHashMap<String, Bundle> getBundlesDirectly() {
		return this.bundles;
	}

	/**
	 * used by {@code LifecycleHibernateTasks}.
	 * 
	 * @return the data source
	 */
	protected HibernateDataSourceImpl getHibernateDatasourceDirectly() {
		return this.hibernateDataSource;
	}

	/**
	 * used by {@code LifecycleHibernateTasks} to inject the data source.
	 * 
	 * @param ds
	 *            the data source
	 */
	protected void setHibernateDataSourceDirectly(
			final HibernateDataSourceImpl ds) {
		this.hibernateDataSource = ds;
	}
	
	/**
	 * used by {@code testStartup} to change to test.xml.
	 * 
	 * @param configurationFile
	 */

	protected void setConfigurationFile(String configurationFile) {
		this.configurationFile = configurationFile;
	}
	
	/**
	 * used by {@code LifecycleMailQueueTasks}.
	 * 
	 * @return the mail queue
	 */
	protected MailQueue getMailQueueDirectly() {
		return this.mailQueue;
	}

	/**
	 * used by {@code LifecycleMailQueueTasks} to inject the mail queue.
	 * 
	 * @param mc
	 *            the mail queue
	 */
	protected void setMailQueueDirectly(final MailQueue mc) {
		this.mailQueue = mc;
	}

	/**
	 * gives internal access to the pulse configuration.
	 * 
	 * @return the pulse configuration
	 */
	protected PulseConfig getPulseConfiguration() {
		return (PulseConfig) PoorMansCache.getConfig(new File(
				this.coreConfigDir, configurationFile));
	}

	/**
	 * sets the JAXBContext.
	 * 
	 * @param ctx
	 *            the JAXBContext to set.
	 */
	protected void setJAXBContext(final JAXBContext ctx) {
		this.jaxbContext = ctx;
	}

	/**
	 * sets the JSONJAXBContext.
	 * 
	 * @param context
	 *            the JSONJAXBContext to be set
	 */
	protected void setJSONJAXBContext(final JSONJAXBContext context) {
		this.jsonJaxbContext = context;
	}

	/**
	 * Converts the given {@code ApplicationLocale}s to {@code Locale}s.
	 * 
	 * @param collection
	 *            the list to be converted
	 * @param onlyActive
	 *            flag indicating whether to return only active locales
	 * 
	 * @return the converted list
	 * 
	 * @see ApplicationLocale
	 */
	protected static Collection<Locale> convertLocaleList(
			final Collection<? extends ApplicationLocale> collection,
			final boolean onlyActive) {

		if (!onlyActive) {
			// default all locales
			return convertLocaleList(collection);
		}

		// active locales only
		Set<ApplicationLocale> activeLocales = new HashSet<ApplicationLocale>();
		for (ApplicationLocale locale : collection) {
			if (locale.isInactive()) {
				continue;
			}
			activeLocales.add(locale);
		}
		return convertLocaleList(activeLocales);
	}

	/**
	 * converts the given list of
	 * {@code org.torweg.pulse.service.request.SystemLocale} to a list of
	 * {@code Locale}.
	 * 
	 * @param collection
	 *            the list to be converted
	 * 
	 * @return the converted list
	 * 
	 * @see SystemLocale
	 */
	protected static Collection<Locale> convertLocaleList(
			final Collection<? extends SystemLocale> collection) {
		Set<Locale> locales = new HashSet<Locale>();
		for (SystemLocale systemLocale : collection) {
			locales.add(LocaleManager.localeToLocale(systemLocale));
		}
		return locales;
	}

	/* --- END: protected direct access methods for Lifecycle tasks --------- */

	/**
	 * actually performs the initialisation of the Lifecycle.
	 */
	private void init() {

		/* create random source */
		createRandom();

		/* initialise the JAXBContext */
		LifecycleJAXBTasks.initialiseJAXBContext(this);

		/* create config pool */
		initialiseLocalCache(this);

		/* initialise the JobletScheduler */
		initializeJobletScheduler();

		/* identify and initialise components */
		initialiseComponents();

		/* identify bundles */
		List<File> bundleDirs = identifyBundles();

		/* initialise bundles */
		LifecycleBundleTasks.initialiseBundles(bundleDirs, this);

		/* re-initialise the JAXBContext */
		LifecycleJAXBTasks.initialiseJAXBContext(this);

		/* initialise Hibernate */
		LifecycleHibernateTasks.initialiseHibernate(this);

		/* initialise ContentRegistry */
		LifecycleHibernateTasks.initialiseRegistries(this);

		/* process annotations */
		LifecycleBundleTasks.processControllerAnnotations(this);

		/* initialise users and groups */
		LifecycleAccessControlTasks.initialiseUsersAndGroups(this);

		/* read main XSL */
		try {
			PoorMansCache.getXSLHandle(new File(this.pulseRootDir
					.getAbsolutePath()
					+ File.separator
					+ "WEB-INF"
					+ File.separator + "xsl" + File.separator + "main.xsl"));
		} catch (Exception e) {
			LOGGER.error(e.getLocalizedMessage(), e);
		}

		/* start the mail queue */
		LifecycleMailQueueTasks.startMailQueue(this);

		/* start the IP to country locator */
		startGeoLocationProvider(this);

		/* initialises the captcha-adapter */
		initializeCaptchaAdapter(this);

		/* initialises the fop-factory-instance */
		initializeFopFactoryInstance(this);

		/* initialises the VFS */
		initialiseVirtualFileSystem();

		/* start the scheduler */
		JobletScheduler.resume();

		/* start the WatchDog, if needed */
		startWatchDog();

	}

	/**
	 * actually performs the shut down process.
	 */
	private void destroy() {
		/* stop the watchdog */
		stopWatchDog(this);

		/* pause scheduler before stopping bundles */
		JobletScheduler.pause();

		/* stop the bundles */
		LifecycleBundleTasks.stopBundles(this);

		/* stop the JobletScheduler */
		stopJobletScheduler();

		/* stop the mail queue */
		LifecycleMailQueueTasks.stopMailQueue(this);

		/* close the hibernate datasource */
		if (this.hibernateDataSource != null) {
			this.hibernateDataSource.close();
		} else {
			LOGGER.warn("The HibernateDataSource was null.");
		}

		/* stop the ip to country service */
		if (this.geoLocationProvider != null) {
			this.geoLocationProvider.shutdown();
		} else {
			LOGGER.info("The GeoLocationProvider was null.");
		}

		/* stop the config pool */
		stopLocalCache();
	}

	/**
	 * creates the default random source.
	 */
	private void createRandom() {
		try {
			random = SecureRandom.getInstance("SHA1PRNG");
			random.nextBytes(new byte[32]); // force internal seeding
		} catch (NoSuchAlgorithmException e) {
			LOGGER.warn(
					"Not using SecureRandom 'SHA1PRNG', falling back to system default: {}",
					e.getLocalizedMessage());
			random = new SecureRandom();
			random.setSeed(random.generateSeed(32));
		}
		lastRandomSeeding = System.currentTimeMillis();
	}

	/**
	 * stops the LocalCache.
	 */
	private void stopLocalCache() {
		LOGGER.trace("Stopping the local cache...");
		if (PoorMansCache.getInstance() != null) {
			((PoorMansCache) PoorMansCache.getInstance()).shutdown();
		} else {
			LOGGER.info("PoorMansCache was null.");
		}
		this.applicationLocales = null; // NOPMD by thomas on 29.02.08 21:31
		LOGGER.info("Local cache stopped.");
	}

	/**
	 * stops the JobletScheduler.
	 */
	private void stopJobletScheduler() {
		LOGGER.trace("Stopping the JobletScheduler...");
		try {
			JobletScheduler.stop();
		} catch (Exception e) {
			LOGGER.error("Cannot stop the JobletScheduler: ", e);
		}
	}

	/**
	 * initialises the WatchDog, if reloading is switched on.
	 */
	private void startWatchDog() {
		PulseConfig servletConfig = getPulseConfiguration();
		if (servletConfig.isReloadable()) {
			LOGGER.trace("Initialising the WatchDog...");
			this.timer = new Timer("Lifecycle.WatchDog");
			this.watchDog = new WatchDog();
			this.timer.scheduleAtFixedRate(this.watchDog,
					servletConfig.getReloadInterval(),
					servletConfig.getReloadInterval());
			LOGGER.info("WatchDog initialised.");
		}
	}

	/**
	 * stops the WatchDog.
	 * 
	 * @param lc
	 *            the lifecycle
	 */
	private void stopWatchDog(final Lifecycle lc) {
		if (lc.timer != null) {
			LOGGER.trace("Stopping the WatchDog...");
			lc.timer.cancel();
			long start = System.currentTimeMillis();
			/* wait up to 30 seconds for the WatchDog to finish */
			while (lc.watchDog.isRunning()
					&& (System.currentTimeMillis() - start < 30000)) {
				try {
					Thread.sleep(100);
				} catch (InterruptedException e) {
					LOGGER.trace("Error stopping the WatchDog: {}",
							e.getLocalizedMessage());
				}
			}
			lc.timer.purge();
			LOGGER.info("WatchDog stopped.");
		} else {
			LOGGER.info("The WatchDog has not been started.");
		}
	}

	/**
	 * initialise the LocalCache.
	 * 
	 * @param lc
	 *            the lifecycle instance
	 */
	private void initialiseLocalCache(final Lifecycle lc) {
		LOGGER.trace("Initialising local cache...");
		PoorMansCache.init(this.coreConfigDir);
		PoorMansCache.getInstance();

		/* get the servlet's configuration */
		PulseConfig pulseConfiguration = getPulseConfiguration();
		LOGGER.info("Local cache initialised with a reload interval of {} ms.",
				pulseConfiguration.getReloadInterval());
		try {
			lc.serverSalt = pulseConfiguration.getServerSalt()
					.getBytes("utf-8");
		} catch (UnsupportedEncodingException e) {
			LOGGER.warn(e.getLocalizedMessage());
			lc.serverSalt = pulseConfiguration.getServerSalt().getBytes();
		}

		// locales
		LocaleManager localeManager = LocaleManager.getInstance();
		lc.applicationLocales = localeManager.getLocales();
		lc.systemLocales = localeManager.getAdditionalSystemLocales();

	}

	/**
	 * starts the JobletScheduler.
	 */
	private void initializeJobletScheduler() {
		LOGGER.trace("Initialising the JobletScheduler...");
		try {
			JobletScheduler.startPaused(getPulseConfiguration()
					.getJobletSchedulerConfiguration());
		} catch (Exception exception) {
			LOGGER.error("Cannot initialise the JobletScheduler: ", exception);
		}
	}

	/**
	 * initialises the IP2CountryProvider.
	 * 
	 * @param lc
	 *            the lifecycle
	 */
	private void startGeoLocationProvider(final Lifecycle lc) {
		/* initialise the IP2CountryProvider */
		try {
			LOGGER.debug("Starting GeoLocationProvider...");
			IGeoLocationProvider locationProvider = getPulseConfiguration()
					.getGeoLocationProvider().newInstance();
			locationProvider.startup();
			lc.geoLocationProvider = locationProvider;
			LOGGER.info("GeoLocationProvider [{}] started.", locationProvider
					.getClass().getCanonicalName());
		} catch (Exception e) {
			LOGGER.error("Could not setup GeoLocationProvider, "
					+ "using NoLookupLocationProvider instead: {}",
					e.getLocalizedMessage());
			this.geoLocationProvider = new NoLookupLocationProvider();
		}
	}

	/**
	 * identifies all component directories.
	 * 
	 * @return the list of component directories
	 */
	private List<File> indentifyComponents() {
		LOGGER.trace("Identifying components...");

		ArrayList<File> identifiedComponents = new ArrayList<File>();
		File[] entries = new File(this.pulseRootDir, "WEB-INF" + File.separator
				+ "components").listFiles();
		if (entries == null) {
			entries = new File[1];
		}

		/* search all subdirectories of the components directory */
		for (File entry : entries) {
			if (entry.isDirectory()) {
				LOGGER.trace("Checking component '" + entry.getName()
						+ "' in '" + entry.getAbsolutePath() + "'.");
				if (new File(entry, "component.xml").exists()) {
					identifiedComponents.add(entry);
					LOGGER.debug("Found component '" + entry.getName()
							+ "' in '" + entry.getAbsolutePath() + "'.");
				} else {
					LOGGER.warn("Missing 'component.xml' in '"
							+ entry.getAbsolutePath()
							+ "' -> Component will not be initialised.");
				}

			}
		}

		/* are there any components? */
		if (identifiedComponents.isEmpty()) {
			LOGGER.error("The container contains no components!");
		}
		return identifiedComponents;
	}

	/**
	 * initialises the components of the container.
	 */
	private void initialiseComponents() {
		Set<Component> localComponents = new HashSet<Component>();
		Unmarshaller unmarshaller;
		try {
			unmarshaller = this.jaxbContext.createUnmarshaller();
		} catch (JAXBException e) {
			throw new LifecycleException("Error initialising Unmarshaller: "
					+ e.getLocalizedMessage(), e);
		}

		for (File configFile : indentifyComponents()) {
			try {
				localComponents.add((Component) unmarshaller
						.unmarshal(new File(configFile, "component.xml")));
			} catch (JAXBException e) {
				throw new LifecycleException("Error initialising component ["
						+ configFile.getName() + "]: "
						+ e.getLocalizedMessage(), e);
			}
		}

		this.components.clear();
		this.components.addAll(localComponents);
	}

	/**
	 * identifies all bundle directories.
	 * 
	 * @return the list of bundle directories
	 */
	private List<File> identifyBundles() {
		LOGGER.trace("Identifying bundles...");

		ArrayList<File> identifiedBundles = new ArrayList<File>();
		File[] entries = this.bundlesRootDir.listFiles();
		if (entries == null) {
			entries = new File[1];
		}

		/* search all subdirectories of the bundle directory */
		for (File entry : entries) {
			if (entry.isDirectory()) {
				LOGGER.trace("Checking bundle '" + entry.getName() + "' in '"
						+ entry.getAbsolutePath() + "'.");
				if (new File(entry, "bundle.xml").exists()) {
					identifiedBundles.add(entry);
					LOGGER.debug("Found bundle '" + entry.getName() + "' in '"
							+ entry.getAbsolutePath() + "'.");
				} else {
					LOGGER.warn("Missing 'bundle.xml' in '"
							+ entry.getAbsolutePath()
							+ "' -> Bundle will not be loaded.");
				}

			}
		}

		/* are there any bundles? */
		if (identifiedBundles.isEmpty()) {
			LOGGER.error("The container contains no bundles!");
		}
		return identifiedBundles;
	}

	/**
	 * initialises the {@code VirtualFileSystem}.
	 */
	private void initialiseVirtualFileSystem() {
		VirtualFileSystem.init(getPulseConfiguration().getVFSConfiguration());
		LOGGER.info("Initialised VirtualFileSystem.");
	}

	/**
	 * Initialises the captcha-adapter.
	 * 
	 * @param lc
	 *            the {@code Lifecycle}
	 */
	private void initializeCaptchaAdapter(final Lifecycle lc) {
		/* initialise the IP2CountryProvider */
		try {

			if (getPulseConfiguration().getCaptchaAdapter() != null) {

				LOGGER.debug("Setting-up captcha-adapter...");

				ICaptchaAdapter<Configuration> adapter = getPulseConfiguration()
						.getCaptchaAdapter().newInstance();

				// configure adapter
				adapter.initialize(PoorMansCache.getConfiguration(new File(
						this.coreConfigDir, adapter.getClass()
								.getCanonicalName() + ".xml")));

				lc.captchaAdapter = adapter;

				LOGGER.info("Captcha-adapter [{}] set up.", adapter.getClass()
						.getCanonicalName());

			} else {
				LOGGER.info("Captcha-adapter: Not configured! Not available! Howto: "
						+ "Add <captcha-adapter class=\"your.available.implementation.of.ICaptchaAdapter\"/> "
						+ "to pulse.xml. "
						+ "Add the your.available.implementation.of.ICaptchaAdapter.xml to WEB-INF/conf.");
			}

		} catch (Exception e) {
			LOGGER.error("Setting-up captcha-adapter has failed: {}",
					e.getLocalizedMessage());
		}
	}

	/**
	 * Initialises the {@code FopFactory}-instance.
	 * 
	 * @param lc
	 *            the {@code Lifecycle}
	 */
	private void initializeFopFactoryInstance(final Lifecycle lc) {
		try {
			// retrieve fop-factory-instance
			FopFactory fopFactory = FopFactory.newInstance();
			// configure the fop-factory if possible
			if (getPulseConfiguration().getFopPath() != null) {
				File file = new File(getBasePath(), getPulseConfiguration()
						.getFopPath());
				// try to configure fop-factory
				if (file.exists()) {
					File fopConf = new File(file, "fop.conf.xml");
					if (fopConf.exists()) {
						fopFactory
								.setUserConfig(new File(file, "fop.conf.xml"));
						LOGGER.info(
								"Configured FopFactory with configuration: {}",
								fopConf.toURI());
					}
					fopFactory.setBaseURL(file.toURI().toString());
					fopFactory.getFontManager().setFontBaseURL(
							file.toURI().toString());
				}
			}
			// set fop-factory for lc
			lc.fopFactoryInstance = fopFactory;
			LOGGER.info("FopFactory uses base-url: " + fopFactory.getBaseURL());
			LOGGER.info("FopFactory uses font-base-url: "
					+ fopFactory.getFontManager().getFontBaseURL());
		} catch (Exception e) {
			LOGGER.error(
					"Initialising FopFactory has failed..."
							+ e.getLocalizedMessage(), e);
		}
	}

	/**
	 * @return Returns the root-directory for the bundles. (for WatchDog)
	 */
	protected File getBundlesRootDir() {
		return this.bundlesRootDir;
	}

	/**
	 * a timer task used to check for changed resources.
	 */
	private class WatchDog extends TimerTask {

		/**
		 * the re-seeding interval.
		 */
		private final long randomReseedingInterval = MillisecondConstant.HOUR
				.getValue();

		/**
		 * flag, indicating whether the task is running.
		 */
		private AtomicBoolean running = new AtomicBoolean(false);

		/**
		 * checks for modified resources.
		 */
		@Override
		public void run() {
			if (!this.running.compareAndSet(false, true)) {
				return;
			}
			try {
				NDC.push("watchdog");
				LOGGER.trace("WatchDog: run()");
				/* check config pool */
				boolean cacheChanges = checkLocalCache((PoorMansCache) PoorMansCache
						.getInstance());

				/* check bundles */
				boolean bundleChanges = checkBundles();

				/*
				 * changes in cache or bundles --> rebuild JAXBContext and
				 * process annotations
				 */
				if (cacheChanges || bundleChanges) {
					LifecycleJAXBTasks.initialiseJAXBContext(lifecycleInstance);
					LifecycleBundleTasks
							.processControllerAnnotations(lifecycleInstance);
				}

				/* check IP to country locator */
				if (geoLocationProvider.isModified()) {
					LOGGER.info("restarting GeoLocationProvider.");
					geoLocationProvider.restart();
				}

				/* re-seed random, if necessary */
				if (System.currentTimeMillis() - lastRandomSeeding > this.randomReseedingInterval) {
					random.setSeed(random.generateSeed(32));
					lastRandomSeeding = System.currentTimeMillis();
					LOGGER.info("Re-seeded random after {}.", TimeSpan
							.stringFromMillis(this.randomReseedingInterval));
				}

			} finally {
				this.running.compareAndSet(true, false);
				NDC.pop();
				NDC.remove();
			}

		}

		/**
		 * returns whether the {@code WatchDog} is running.
		 * 
		 * @return {@code true}, if the {@code WatchDog} is running. Otherwise
		 *         {@code false}.
		 */
		public final boolean isRunning() {
			return this.running.get();
		}

		/**
		 * checks the config pool for changes.
		 * 
		 * @param pool
		 *            the config pool
		 * @return {@code true}, if changes occurred
		 */
		private boolean checkLocalCache(final PoorMansCache pool) {
			if (pool.isModified()) {
				pool.restart();
				LOGGER.info("WatchDog: Config pool reloaded.");
				/* reconfigure MailQueue */
				reconfigureMailQueue();
				/* reload IP2CountryLocator, if necessary */
				geoLocationProvider.restart();
				return true;
			}
			return false;
		}

		/**
		 * reconfigure the MailQueue.
		 */
		private void reconfigureMailQueue() {
			MailQueueConfiguration conf = new MailQueueConfiguration();
			conf.init(getPulseConfiguration().getMailQueueConfiguration());
			conf.setPulseRootDir(getBasePath());
			getMailQueue().reconfigure(conf);
		}

		/**
		 * checks the bundles for changes and reloads if necessary.
		 * 
		 * @return {@code true}, if changes occurred
		 */
		private boolean checkBundles() {
			File[] bundleDirectories = getBundlesRootDir().listFiles();
			if (bundleDirectories == null) {
				LOGGER.debug("Bundle check aborted: Could not list bundle directory.");
				return false;
			}
			ArrayList<File> possibleBundles = new ArrayList<File>(
					Arrays.asList(bundleDirectories));
			/* check previously loaded bundles first */
			boolean initializedBundles = checkInitializedBundles(possibleBundles);

			/* check remaining directory entries from the bundle root directory */
			boolean newBundles = checkNewBundles(possibleBundles);

			return (initializedBundles | newBundles);
		}

		/**
		 * checks all newly found {@code Bundle}s and tries to start them up.
		 * 
		 * @param newBundles
		 *            the new bundles
		 * @return {@code true}, if changes occurred
		 */
		private boolean checkNewBundles(final List<File> newBundles) {
			boolean changed = false;
			for (File f : newBundles) {
				if ((f.isDirectory()) && (new File(f, "bundle.xml").exists())) {
					try {
						Bundle bundle = LifecycleBundleTasks.initBundle(f,
								lifecycleInstance);
						lifecycleInstance.bundles.put(bundle.getName(), bundle);
						LOGGER.info("WatchDog: Bundle '{}' loaded.",
								bundle.getName());
						changed = true;
					} catch (LifecycleException e) {
						LOGGER.error(
								"WatchDog: Bundle defined in '"
										+ f.getAbsolutePath()
										+ "' cannot be loaded.", e);
					}
				}
			}
			return changed;
		}

		/**
		 * checks all initialised {@code Bundle}s for modifications and reloads
		 * them, if necessary.
		 * 
		 * @param initializedBundles
		 *            the initialised bundles
		 * @return {@code true}, if modifications were detected
		 */
		private boolean checkInitializedBundles(
				final List<File> initializedBundles) {
			boolean changed = false;
			for (Bundle bundle : getBundles()) {
				if (!bundle.getDirectory().exists()) {
					/* bundle does not exist anymore */
					PoorMansCache.flushBundle(bundle);
					changed = true;
				} else if (bundle.isModified()) {
					PoorMansCache.flushBundle(bundle);
					/* bundle has been modified */
					initializedBundles.remove(bundle.getDirectory());
					try {
						bundle.restart();
						LOGGER.info("WatchDog: Bundle '{}' reloaded.",
								bundle.getName());
						changed = true;
					} catch (LifecycleException e) {
						LOGGER.error("WatchDog: Bundle '" + bundle.getName()
								+ "' cannot be reloaded.", e);
					}
				} else {
					/* bundle exists and has not been modified */
					initializedBundles.remove(bundle.getDirectory());
				}
			}
			return changed;
		}
	}

}

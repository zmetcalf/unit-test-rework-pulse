/*
 * Copyright 2009 :torweg free software group
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
package org.torweg.pulse;

import java.io.File;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.NDC;
import org.torweg.pulse.invocation.lifecycle.Lifecycle;

/**
 * creates a {@code Lifecycle} for unit-test.
 * 
 * <p>
 * <strong>This class requires the dist directory to be built.</strong>
 * </p>
 * 
 * @author Thomas Weber
 * @version $Revision: 1437 $
 */
public final class TestingEnvironment {

	/**
	 * initialises the test environment.
	 */
	static {
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.WARN);
		Logger.getLogger("org.torweg.pulse").setLevel(Level.INFO);
		NDC.push("startup");
		try {
			Lifecycle.testStartup(new File(TestConstants.MAIN_DIST()));
		} finally {
			NDC.pop();
			NDC.remove();
		}
	}

	public TestingEnvironment() {
		super();
	}

}
